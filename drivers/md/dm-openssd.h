/*
 * Copyright (C) 2012 Matias Bjørling.
 *
 * This file is released under the GPL.
 */

#ifndef DM_OPENSSD_H_
#define DM_OPENSSD_H_
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
#include <linux/percpu-refcount.h>
#endif
#define OPENSSD_IOC_MAGIC 'O'

#define OPENSSD_IOCTL_ID          _IO(OPENSSD_IOC_MAGIC, 0x40)
#define OPENSSD_IOCTL_SUBMIT_HINT _IOW(OPENSSD_IOC_MAGIC, 0x41, hint_data_t)
#define OPENSSD_IOCTL_KERNEL_HINT _IOW(OPENSSD_IOC_MAGIC, 0x42, hint_data_t)

#ifdef __KERNEL__
#define DM_MSG_PREFIX "openssd"

#define APS_PER_POOL 1 /* Number of append points per pool. We assume that accesses within
						  a pool is serial (NAND flash / PCM / etc.) */
#define SERIALIZE_POOL_ACCESS 0 /* If enabled, we delay bios on each ap to run serialized. */
#define LTOP_EMPTY -1

/* Sleep timings before simulating device specific storage (in us)*/
#define TIMING_READ 25
#define TIMING_WRITE 500
#define TIMING_ERASE 1500

/* Run GC every X seconds */
#define GC_TIME 10
/* Run only GC is less than 1/X blocks are free */
#define GC_LIMIT_INVERSE 2

/*
 * For now we hardcode the configuration for the OpenSSD unit that we own. In
 * the future this should be made configurable.
 *
 * Configuration:
 *
 * Physical address space is divided into 8 chips. I.e. we create 8 pools for the
 * addressing. We also omit the first block of each chip as they contain
 * either the drive firmware or recordings of bad blocks.
 *
 * BLOCK_PAGE_COUNT must be a power of two.
 */

#define DEVICE_PAGE_SIZE 512	/* The minimum page size we communicate with to the physical disk */
#define EXPOSED_PAGE_SIZE 4096	/* The page size that we expose to the operating system */
#define FLASH_PAGE_SIZE 8196	/* The size of the physical flash page */

#define POOL_COUNT 8
#define POOL_BLOCK_COUNT 4
#define BLOCK_PAGE_COUNT 64

/*---------------------
 * Swap hints. TODO: all this should move to configuration files, etc.
 *
 * different timings, roughly based on "Harey Tortoise" paper (TODO: ratio is actually 4.8 on average)
 *------------------- */
#define TIMING_WRITE_FAST (TIMING_WRITE / 2)
#define TIMING_WRITE_SLOW (TIMING_WRITE * 2)

#define NR_HOST_PAGES_IN_FLASH_PAGE (FLASH_PAGE_SIZE / EXPOSED_PAGE_SIZE)
#define NR_PHY_IN_LOG (EXPOSED_PAGE_SIZE / 512)
#define NR_HOST_PAGES_IN_BLOCK (NR_HOST_PAGES_IN_FLASH_PAGE * BLOCK_PAGE_COUNT)

enum ltop_flags {
	MAP_PRIMARY	= 1 << 0, /* Update primary mapping (and init secondary mapping as a result) */
	MAP_SHADOW	= 1 << 1, /* Update only shaddow mapping */
	MAP_SINGLE	= 1 << 2, /* Update only the relevant mapping (primary/shaddow) */
};

/* Pool descriptions */
struct openssd_pool_block {
	struct {
		spinlock_t lock;
		unsigned int next_page; /* points to the next writable flash page within a block */
		unsigned char next_offset; /* if a flash page can have multiple host pages,
									   fill up the flash page before going to the next
									   writable flash page */
		unsigned int nr_invalid_pages; /* number of pages that are invalid, with respect to host page size */
		unsigned long invalid_pages[NR_HOST_PAGES_IN_BLOCK / BITS_PER_LONG];

		/* no need to sync. Move down if it overflow the cacheline */
		struct openssd_pool *parent;
		unsigned int id;
	} ____cacheline_aligned_in_smp;

	// Management and GC structures
	struct list_head list;
	struct list_head prio;

	// Persistent data structures
	struct page *data;
	atomic_t data_size; /* data pages inserted into data variable */
	atomic_t data_cmnt_size; /* data pages committed to stable storage */

	/* Block state handling */
	spinlock_t gc_lock;
	struct percpu_ref ref_count; /* Outstanding IOs to be completed on block */
};

struct openssd_addr {
	sector_t addr;
	struct openssd_pool_block *block;
};

struct openssd_pool {
	/* Pool block lists */
	struct {
		spinlock_t lock;
		struct list_head used_list;	/* In-use blocks */
		struct list_head free_list;	/* Not used blocks i.e. released and ready for use */
		struct list_head prio_list;	/* Prioritized list of blocks. Sorted according to cost/benefit. */
	} ____cacheline_aligned_in_smp;

	unsigned long phy_addr_start;	/* References the physical start block */
	unsigned int phy_addr_end;		/* References the physical end block */

	unsigned int nr_blocks;			/* Derived value from end_block - start_block. */
	unsigned int nr_free_blocks;	/* Number of unused blocks */

	struct openssd_pool_block *blocks;

	/* Postpone issuing I/O if append point is active */
	atomic_t is_active;
	struct work_struct waiting_ws;
	spinlock_t waiting_lock;
	struct bio_list waiting_bios;
};

/*
 * openssd_ap. ap is an append point. A pool can have 1..X append points attached.
 * An append point has a current block, that it writes to, and when its full, it requests
 * a new block, of which it continues its writes.
 */
struct openssd_ap {
	spinlock_t lock;
	struct openssd *parent;
	struct openssd_pool *pool;
	struct openssd_pool_block *cur;

	/* Timings used for end_io waiting */
	unsigned long t_read;
	unsigned long t_write;
	unsigned long t_erase;

	unsigned long io_delayed;
	unsigned long io_accesses[2];
};

struct openssd;

typedef sector_t (map_ltop_fn)(struct openssd *, sector_t, struct openssd_pool_block **, void *);
typedef struct openssd_addr *(lookup_ltop_fn)(struct openssd *, sector_t);
typedef sector_t (lookup_ptol_fn)(struct openssd *, sector_t);
typedef int (write_bio_fn)(struct openssd *, struct bio *);
typedef int (read_bio_fn)(struct openssd *, struct bio *);

/* Main structure */
struct openssd {
	struct dm_dev *dev;
	struct dm_target *ti;
	uint32_t sector_size;

	/* Simple translation map of logical addresses to physical addresses. The
	 * logical addresses is known by the host system, while the physical
	 * addresses are used when writing to the disk block device. */
	struct openssd_addr *trans_map;
	/* also store a reverse map for garbage collection */
	sector_t *rev_trans_map;

	/* Usually instantiated to the number of available parallel channels
	 * within the hardware device. i.e. a controller with 4 flash channels,
	 * would have 4 pools.
	 *
	 * We assume that the device exposes its channels as a linear address
	 * space. A pool therefore have a phy_addr_start and phy_addr_end that
	 * denotes the start and end. This abstraction is used to let the openssd
	 * (or any other device) expose its read/write/erase interface and be
	 * administrated by the host system.
	 */
	struct openssd_pool *pools;

	/* Append points */
	struct openssd_ap *aps;

	mempool_t *per_bio_pool;

	int nr_pools;
	int nr_aps;
	int nr_aps_per_pool;

	unsigned long nr_pages;

	unsigned int next_collect_pool;
	/* FTL interface */
	map_ltop_fn *map_ltop;
	lookup_ltop_fn *lookup_ltop;
	lookup_ptol_fn *lookup_ptol;
	write_bio_fn *write_bio;
	read_bio_fn *read_bio;

	/* Write strategy variables. Move these into each for structure for each
	 * strategy */
	atomic_t next_write_ap; /* Whenever a page is written, this is updated to point
							   to the next write append point */

	bool serialize_pool_access;		/* Control accesses to append points in the host.
							 * Enable this for devices that doesn't have an
							 * internal queue that only lets one command run
							 * at a time within an append point
							*/
	struct workqueue_struct *kbiod_wq;

	spinlock_t gc_lock;
	struct task_struct *kt_openssd; /* handles gc and any other async work */

	/* Hint related*/
	void *hint_private;
};

static struct kmem_cache *_per_bio_cache;

struct per_bio_data {
	struct openssd_ap *ap;
	struct openssd_pool_block *block;
	struct timeval start_tv;
	sector_t physical_addr;

	// Hook up for our overwritten bio fields
	bio_end_io_t *bi_end_io;
	void *bi_private;
	struct completion event;
	unsigned int sync;
};

/* dm-openssd-c */

/*   Helpers */
void openssd_print_total_blocks(struct openssd *os);

void openssd_set_ap_cur(struct openssd_ap *ap, struct openssd_pool_block *block);
struct openssd_pool_block *openssd_pool_get_block(struct openssd_pool *pool);
sector_t openssd_alloc_phys_addr(struct openssd_pool_block *block);
sector_t openssd_alloc_phys_fastest_addr(struct openssd *os, struct openssd_pool_block **ret_victim_block);

/*   Naive implementations */
void openssd_delayed_bio_submit(struct work_struct *work);

/* Allocation of physical addresses from block when increasing responsibility. */
sector_t openssd_alloc_addr_from_ap(struct openssd_ap *ap, struct openssd_pool_block **ret_victim_block);
sector_t openssd_alloc_ltop_rr(struct openssd *os, sector_t logical_addr, struct openssd_pool_block **ret_victim_block, void *private);
sector_t openssd_alloc_map_ltop_rr(struct openssd *os, sector_t logical_addr, struct openssd_pool_block **ret_victim_block, void *private);
/* Calls map_ltop_rr with a specified number of retries. Returns LTOP_EMPTY if failed */
sector_t openssd_alloc_addr_retries(struct openssd *os, sector_t logical_addr, struct openssd_pool_block **ret_victim_block, void *private);

/* Gets an address from os->trans_map and take a ref count on the blocks usage. Remember to put later */
struct openssd_addr *openssd_lookup_ltop(struct openssd *os, sector_t logical_addr);
sector_t openssd_lookup_ptol(struct openssd *os, sector_t physical_addr);

/*   I/O bio related */
void openssd_submit_bio(struct openssd *os, struct openssd_pool_block *block, int rw, struct bio *bio, int sync);
void openssd_submit_write(struct openssd *os, sector_t physical_addr,
				 struct openssd_pool_block* victim_block, int size);
int openssd_handle_buffered_write(sector_t physical_addr, struct openssd_pool_block *victim_block, struct bio_vec *bv);
int openssd_write_bio_generic(struct openssd *os, struct bio *bio);
int openssd_read_bio_generic(struct openssd *os, struct bio *bio);
void openssd_update_map_generic(struct openssd *os,  sector_t l_addr,
				   sector_t p_addr, struct openssd_pool_block *p_block);

/*   NVM device related */
void openssd_block_release(struct percpu_ref *);

/*   Block maintanence */

void openssd_pool_put_block(struct openssd_pool_block *block);
void openssd_reset_block(struct openssd_pool_block *block);

/* dm-openssd-gc.c */
void openssd_block_erase(struct kref *);
void openssd_gc_collect(struct openssd *os);


/* dm-openssd-hint.c */
int openssd_alloc_hint(struct openssd *);
int openssd_init_hint(struct openssd *);
void openssd_exit_hint(struct openssd *);
void openssd_free_hint(struct openssd *);

/*   Hint core */
int openssd_ioctl_hint(struct openssd *os, unsigned int cmd, unsigned long arg);

/*   Callbacks */
void openssd_delay_endio_hint(struct openssd *os, struct bio *bio, struct per_bio_data *pb, unsigned long *delay);
void openssd_bio_hint(struct openssd *os, struct bio *bio);

#define ssd_for_each_pool(openssd, pool, i)									\
		for ((i) = 0, pool = &(openssd)->pools[0];							\
			 (i) < (openssd)->nr_pools; (i)++, pool = &(openssd)->pools[(i)])

#define ssd_for_each_ap(openssd, ap, i)										\
		for ((i) = 0, ap = &(openssd)->aps[0];								\
			 (i) < (openssd)->nr_aps; (i)++, ap = &(openssd)->aps[(i)])

#define pool_for_each_block(pool, block, i)									\
		for ((i) = 0, block = &(pool)->blocks[0];							\
			 (i) < (pool)->nr_blocks; (i)++, block = &(pool)->blocks[(i)])

static inline struct openssd_ap *get_next_ap(struct openssd *os)
{
	return &os->aps[atomic_inc_return(&os->next_write_ap) % os->nr_aps];
}

static inline int block_is_full(struct openssd_pool_block *block)
{
	return ((block->next_page * NR_HOST_PAGES_IN_FLASH_PAGE) + block->next_offset == NR_HOST_PAGES_IN_BLOCK);
}

static inline sector_t block_to_addr(struct openssd_pool_block *block)
{
	return (block->id * NR_HOST_PAGES_IN_BLOCK);
}

static inline int page_is_fast(unsigned int pagenr)
{
	/* pages: F F F F | SSFFSS | SSFFSS | ... S Slow F Fast */
	if (pagenr < 4)
		return 1;

	pagenr -= 4;
	pagenr %= 6;

	if (pagenr == 2 || pagenr == 3)
		return 1;

	return 0;
}

static inline struct openssd_ap *block_to_ap(struct openssd *os, struct openssd_pool_block *block)
{
	unsigned int ap_idx, div, mod;

	div = block->id / POOL_BLOCK_COUNT;
	mod = block->id % POOL_BLOCK_COUNT;
	ap_idx = div + (mod / (POOL_BLOCK_COUNT / APS_PER_POOL));

	return &os->aps[ap_idx];
}

static inline int physical_to_slot(sector_t phys)
{
	return (phys % (BLOCK_PAGE_COUNT * NR_HOST_PAGES_IN_FLASH_PAGE)) / NR_HOST_PAGES_IN_FLASH_PAGE;
}

static inline void openssd_get_block(struct openssd_pool_block *block)
{
	return percpu_ref_get(&block->ref_count);
}

static inline void openssd_put_block(struct openssd_pool_block *block)
{
	percpu_ref_put(&block->ref_count);
}
#endif

#endif /* DM_OPENSSD_H_ */
