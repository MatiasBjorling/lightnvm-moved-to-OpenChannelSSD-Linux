/*
 * Copyright (C) 2012 Matias Bjørling.
 *
 * This file is released under the GPL.
 */

#ifndef DM_LIGHTNVM_H_
#define DM_LIGHTNVM_H_

#define LIGHTNVM_IOC_MAGIC 'O'
#define LIGHTNVM_IOCTL_ID          _IO(LIGHTNVM_IOC_MAGIC, 0x40)

#ifdef __KERNEL__
#include <linux/device-mapper.h>
#include <linux/dm-io.h>
#include <linux/dm-kcopyd.h>
#include <linux/blkdev.h>
#include <linux/list.h>
#include <linux/list_sort.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/atomic.h>
#include <linux/delay.h>
#include <linux/time.h>
#include <linux/workqueue.h>
#include <linux/kthread.h>
#include <linux/mempool.h>
#include <linux/kref.h>
#include <linux/completion.h>
#include <linux/hashtable.h>

#define DM_MSG_PREFIX "lightnvm"
#define LTOP_EMPTY -1
#define LTOP_POISON 3133731337


/*
 * For now we hardcode some of the configuration for the LightNVM device that we
 * have. In the future this should be made configurable.
 *
 * Configuration:
 * EXPOSED_PAGE_SIZE - the page size of which we tell the layers above the
 * driver to issue. This usually is 512 bytes for 4K for simplivity.
 * FLASH_PAGE_SIZE - the flash size of the individual flash pages. These should
 * match the hardware flash chips. Currently only the same page size as
 * EXPOSED_PAGE_SIZE is supported.
 *
 */

#define EXPOSED_PAGE_SIZE 4096
#define FLASH_PAGE_SIZE EXPOSED_PAGE_SIZE


/* Useful shorthands */
#define NR_HOST_PAGES_IN_FLASH_PAGE (FLASH_PAGE_SIZE / EXPOSED_PAGE_SIZE)
/* We currently assume that we the lightnvm device is accepting data in 512
 * bytes chunks. This should be set to the smallest command size available for a
 * given device.
 */
#define NR_PHY_IN_LOG (EXPOSED_PAGE_SIZE / 512)

enum ltop_flags {
	MAP_PRIMARY	= 1 << 0, /* Update primary mapping (and init secondary mapping as a result) */
	MAP_SHADOW	= 1 << 1, /* Update only shaddow mapping */
	MAP_SINGLE	= 1 << 2, /* Update only the relevant mapping (primary/shaddow) */
};

#define NVM_WRITE_SUCCESS  0
#define NVM_WRITE_DEFERRED 1
#define NVM_WRITE_GC_ABORT 2

#define NVM_OPT_MISC_OFFSET 15

enum target_flags {
	/* No hints applied */
	NVM_OPT_ENGINE_NONE		= 0 <<  0,
	/* Swap aware hints. Detected from block request type */
	NVM_OPT_ENGINE_SWAP		= 1 <<  0,
	/* IOCTL aware hints. Applications may submit direct hints */
	NVM_OPT_ENGINE_IOCTL	= 1 <<  1,
	/* Latency aware hints. Detected from file type or directly from app */
	NVM_OPT_ENGINE_LATENCY	= 1 <<  2,
	/* Pack aware hints. Detected from file type or directly from app */
	NVM_OPT_ENGINE_PACK	= 1 <<  3,

	/* Control accesses to append points in the host. Enable this for
	 * devices that doesn't have an internal queue that only lets one
	 * command run at a time within an append point */
	NVM_OPT_POOL_SERIALIZE	= 1 << NVM_OPT_MISC_OFFSET,
	/* Use fast/slow page access pattern */
	NVM_OPT_FAST_SLOW_PAGES	= 1 << (NVM_OPT_MISC_OFFSET+1),
	/* Disable dev waits */
	NVM_OPT_NO_WAITS	= 1 << (NVM_OPT_MISC_OFFSET+2),
};

/* Pool descriptions */
struct nvm_block {
	struct {
		spinlock_t lock;
		/* points to the next writable flash page within a block */
		unsigned int next_page;
		/* if a flash page can have multiple host pages,
		   fill up the flash page before going to the next
		   writable flash page */
		unsigned char next_offset;
		/* number of pages that are invalid, with respect to host page size */
		unsigned int nr_invalid_pages;
#define MAX_INVALID_PAGES_STORAGE 8
		/* Bitmap for invalid page intries */
		unsigned long invalid_pages[MAX_INVALID_PAGES_STORAGE];
	} ____cacheline_aligned_in_smp;

	unsigned int id;
	struct nvm_pool *pool;
	struct nvm_ap *ap;

	// Management and GC structures
	struct list_head list;
	struct list_head prio;

	// Persistent data structures
	struct page *data;
	atomic_t data_size; /* data pages inserted into data variable */
	atomic_t data_cmnt_size; /* data pages committed to stable storage */

	/* Block state handling */
	atomic_t gc_running;
	struct kref ref_count; /* Outstanding IOs to be completed on block */
	struct work_struct ws_gc;
};

/* Logical to physical mapping */
struct nvm_addr {
	sector_t addr;
	struct nvm_block *block;
	atomic_t inflight;
};

/* Physical to logical mapping */
struct nvm_rev_addr {
	sector_t addr;
	struct nvm_addr *trans_map;
};

struct nvm_pool {
	/* Pool block lists */
	struct {
		spinlock_t lock;
	} ____cacheline_aligned_in_smp;
	struct {
		spinlock_t gc_lock;
	} ____cacheline_aligned_in_smp;

	struct list_head used_list;	/* In-use blocks */
	struct list_head free_list;	/* Not used blocks i.e. released and ready for use */
	struct list_head prio_list;	/* Blocks that may be GC'ed. */

	unsigned int id;
	unsigned long phy_addr_start;	/* References the physical start block */
	unsigned int phy_addr_end;		/* References the physical end block */

	unsigned int nr_blocks;			/* Derived value from end_block - start_block. */
	unsigned int nr_free_blocks;	/* Number of unused blocks */

	unsigned int nr_gc_blocks;	/* Number of blocks undergoing gc*/

	struct nvm_block *blocks;
	struct nvmd *nvmd;

	/* Postpone issuing I/O if append point is active */
	atomic_t is_active;

	spinlock_t waiting_lock;
	struct work_struct waiting_ws;
	struct work_struct execute_ws;
	struct bio_list waiting_bios;

	unsigned int gc_running;
	struct completion gc_finished;
	struct work_struct gc_ws;
};

/*
 * nvm_ap. ap is an append point. A pool can have 1..X append points attached.
 * An append point has a current block, that it writes to, and when its full, it requests
 * a new block, of which it continues its writes.
 *
 * one ap per pool may be reserved for pack-hints related writes. 
 * In those that are not not, hint_private is NULL.
 */
struct nvm_ap {
	spinlock_t lock;
	struct nvmd *parent;
	struct nvm_pool *pool;
	struct nvm_block *cur;
	struct nvm_block *gc_cur;

	/* Timings used for end_io waiting */
	unsigned long t_read;
	unsigned long t_write;
	unsigned long t_erase;

	unsigned long io_delayed;
	unsigned long io_accesses[2];

	/* Hint related*/
	void *hint_private;
};

struct nvm_config {
	unsigned long flags;

	unsigned int gc_time;		/* GC every X microseconds */

	unsigned int t_read;
	unsigned int t_write;
	unsigned int t_erase;
};

struct nvmd;
struct per_bio_data;

typedef struct nvm_addr *(map_ltop_fn)(struct nvmd *, sector_t, int, struct nvm_addr *, void *private);
typedef struct nvm_addr *(lookup_ltop_fn)(struct nvmd *, sector_t);
typedef struct nvm_rev_addr *(lookup_ptol_fn)(struct nvmd *, sector_t);
typedef int (write_bio_fn)(struct nvmd *, struct bio *);
typedef int (read_bio_fn)(struct nvmd *, struct bio *);
typedef void (alloc_phys_addr_fn)(struct nvmd *, struct nvm_block *);
typedef void *(begin_gc_private_fn)(struct nvmd *, sector_t, sector_t, struct nvm_block *);
typedef void (end_gc_private_fn)(struct nvmd *, void *);
typedef void (defer_bio_fn)(struct nvmd *, struct bio *);

/* Main structure */
struct nvmd {
	struct dm_dev *dev;
	struct dm_target *ti;
	uint32_t sector_size;

	/* Simple translation map of logical addresses to physical addresses. The
	 * logical addresses is known by the host system, while the physical
	 * addresses are used when writing to the disk block device. */
	struct nvm_addr *trans_map;
	/* also store a reverse map for garbage collection */
	struct nvm_rev_addr *rev_trans_map;

	spinlock_t trans_lock;
	/* Usually instantiated to the number of available parallel channels
	 * within the hardware device. i.e. a controller with 4 flash channels,
	 * would have 4 pools.
	 *
	 * We assume that the device exposes its channels as a linear address
	 * space. A pool therefore have a phy_addr_start and phy_addr_end that
	 * denotes the start and end. This abstraction is used to let the
	 * lightnvm (or any other device) expose its read/write/erase interface
	 * and be administrated by the host system.
	 */
	struct nvm_pool *pools;

	/* Append points */
	struct nvm_ap *aps;

	mempool_t *per_bio_pool;
	mempool_t *addr_pool;
	mempool_t *page_pool;
	mempool_t *block_page_pool;

	/* Frequently used config variables */
	int nr_pools;
	int nr_blks_per_pool;
	int nr_pages_per_blk;
	int nr_aps;
	int nr_aps_per_pool;

	/* Calculated values */
	unsigned int nr_host_pages_in_blk;
	unsigned long nr_pages;

	unsigned int next_collect_pool;

	/* Engine interface */
	map_ltop_fn *map_ltop;
	lookup_ltop_fn *lookup_ltop;
	lookup_ptol_fn *lookup_ptol;
	write_bio_fn *write_bio;
	read_bio_fn *read_bio;
	alloc_phys_addr_fn *alloc_phys_addr;
	begin_gc_private_fn *begin_gc_private;
	end_gc_private_fn *end_gc_private;
	defer_bio_fn *defer_bio;
	/* Write strategy variables. Move these into each for structure for each
	 * strategy */
	atomic_t next_write_ap; /* Whenever a page is written, this is updated to point
							   to the next write append point */

	struct workqueue_struct *kbiod_wq;
	struct workqueue_struct *kgc_wq;

	spinlock_t deferred_lock;
	struct work_struct deferred_ws;
	struct bio_list deferred_bios;

	struct timer_list gc_timer;

	/* in-flight data lookup, lookup by logical address */
	struct hlist_head *inflight;

	/* Hint related*/
	void *hint_private;

	/* Configuration */
	struct nvm_config config;
};

struct per_bio_data {
	struct nvm_ap *ap;
	struct nvm_addr *addr;
	struct timespec start_tv;
	sector_t l_addr;

	// Hook up for our overwritten bio fields
	bio_end_io_t *bi_end_io;
	void *bi_private;
	struct completion *event;
	struct bio *orig_bio;
	unsigned int sync;
	unsigned int ref_put;
	struct nvm_addr *trans_map;
};

/* dm-lightnvm-c */

/*   Helpers */
void invalidate_block_page(struct nvmd *, struct nvm_addr *);
void nvm_set_ap_cur(struct nvm_ap *, struct nvm_block *);
struct nvm_block *nvm_pool_get_block(struct nvm_pool *, int is_gc);
sector_t nvm_alloc_phys_addr(struct nvm_block *);
struct nvm_addr *nvm_alloc_phys_fastest_addr(struct nvmd *);
void nvm_defer_bio(struct nvmd *nvmd, struct bio *bio);

/*   Naive implementations */
void nvm_delayed_bio_submit(struct work_struct *work);
void nvm_delayed_bio_defer(struct work_struct *work);
void nvm_deferred_bio_submit(struct work_struct *work);
void nvm_gc_block(struct work_struct *work);

/* Allocation of physical addresses from block when increasing responsibility. */
struct nvm_addr *nvm_alloc_addr_from_ap(struct nvm_ap *, int is_gc);
struct nvm_addr *nvm_map_ltop_rr(struct nvmd *, sector_t l_addr, int is_gc, struct nvm_addr *trans_map, void *private);

/* Gets an address from nvm->trans_map and take a ref count on the blocks usage. Remember to put later */
struct nvm_addr *nvm_lookup_ltop_map(struct nvmd *, sector_t l_addr, struct nvm_addr *l2p_map);
struct nvm_addr *nvm_lookup_ltop(struct nvmd *, sector_t l_addr);
struct nvm_rev_addr *nvm_lookup_ptol(struct nvmd *, sector_t p_addr);

/*   I/O bio related */
void nvm_submit_bio(struct nvmd *, struct nvm_addr *, sector_t, int rw, struct bio *, struct bio *orig_bio, struct completion *sync);
struct bio *nvm_write_init_bio(struct nvmd *, struct bio *bio, struct nvm_addr *p);
int nvm_bv_copy(struct nvm_addr *p, struct bio_vec *bv);
int nvm_write_execute_bio(struct nvmd *, struct bio *bio, int is_gc, void *private, struct completion *sync, struct nvm_addr *trans_map, unsigned int complete_bio);
int nvm_write_bio(struct nvmd *, struct bio *bio);
int nvm_read_bio(struct nvmd *, struct bio *bio);
int nvm_update_map(struct nvmd *nvmd, sector_t l_addr, struct nvm_addr *p, int is_gc, struct nvm_addr *trans_map);
struct nvm_addr *nvm_get_trans_map(struct nvmd *nvmd, void *private);
void nvm_defer_write_bio(struct nvmd *nvmd, struct bio *bio, void *private);

/*   NVM device related */
void nvm_block_release(struct kref *);

/*   Block maintanence */

void nvm_pool_put_block(struct nvm_block *);
void nvm_reset_block(struct nvm_block *);

/* dm-lightnvm-gc.c */
void nvm_block_erase(struct kref *);
void nvm_gc_cb(unsigned long data);
void nvm_gc_collect(struct work_struct *work);
void nvm_gc_kick(struct nvmd *nvmd);


/* dm-lightnvm-hint.c */
int nvm_alloc_hint(struct nvmd *);
int nvm_init_hint(struct nvmd *);
void nvm_exit_hint(struct nvmd *);
void nvm_free_hint(struct nvmd *);

/*   Hint core */
int nvm_ioctl_hint(struct nvmd *, unsigned int cmd, unsigned long arg);

/*   Callbacks */
void nvm_delay_endio_hint(struct nvmd *, struct bio *bio, struct per_bio_data *pb, unsigned long *delay);
void nvm_bio_hint(struct nvmd *, struct bio *bio);

#define ssd_for_each_pool(nvmd, pool, i)									\
		for ((i) = 0, pool = &(nvmd)->pools[0];							\
			 (i) < (nvmd)->nr_pools; (i)++, pool = &(nvmd)->pools[(i)])

#define ssd_for_each_ap(nvmd, ap, i)										\
		for ((i) = 0, ap = &(nvmd)->aps[0];								\
			 (i) < (nvmd)->nr_aps; (i)++, ap = &(nvmd)->aps[(i)])

#define pool_for_each_block(pool, block, i)									\
		for ((i) = 0, block = &(pool)->blocks[0];							\
			 (i) < (pool)->nr_blocks; (i)++, block = &(pool)->blocks[(i)])

static inline struct nvm_ap *get_next_ap(struct nvmd *nvmd) {
	return &nvmd->aps[atomic_inc_return(&nvmd->next_write_ap) % nvmd->nr_aps];
}

static inline int block_is_full(struct nvm_block *block)
{
	struct nvmd *nvmd = block->pool->nvmd;
	return ((block->next_page * NR_HOST_PAGES_IN_FLASH_PAGE) +
			block->next_offset == nvmd->nr_host_pages_in_blk);
}

static inline sector_t block_to_addr(struct nvm_block *block)
{
	struct nvmd *nvmd;
	BUG_ON(!block);
	nvmd = block->pool->nvmd;
	return block->id * nvmd->nr_host_pages_in_blk;
}

static inline int page_is_fast(struct nvmd *nvmd, unsigned int pagenr)
{
	/* pages: F F F F | SSFFSS | SSFFSS | ... | S S S S . S Slow F Fast */
	if (pagenr < 4)
		return 1;

	if (pagenr >= nvmd->nr_pages_per_blk - 4)
		return 0;

	pagenr -= 4;
	pagenr %= 4;

	if (pagenr == 2 || pagenr == 3) 
		return 1;
	
	return 0;
}

static inline struct nvm_pool *paddr_to_pool(struct nvmd *nvmd, sector_t p_addr){
	return &nvmd->pools[p_addr / (nvmd->nr_pages / nvmd->nr_pools)];
}

static inline struct nvm_ap *block_to_ap(struct nvmd *nvmd, struct nvm_block *block) {
	unsigned int ap_idx, div, mod;

	div = block->id / nvmd->nr_blks_per_pool;
	mod = block->id % nvmd->nr_blks_per_pool;
	ap_idx = div + (mod / (nvmd->nr_blks_per_pool / nvmd->nr_aps_per_pool));

	return &nvmd->aps[ap_idx];
}

static inline int physical_to_slot(struct nvmd *nvm, sector_t phys)
{
	return (phys % (nvm->nr_pages_per_blk * NR_HOST_PAGES_IN_FLASH_PAGE)) /
		NR_HOST_PAGES_IN_FLASH_PAGE;
}

#endif

#endif /* DM_LIGHTNVM_H_ */

