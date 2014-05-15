/*
 * Copyright (C) 2014 Matias Bjørling.
 *
 * This file is released under the GPL.
 */

#ifndef LIGHTNVM_H_
#define LIGHTNVM_H_

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
#include <linux/percpu_ida.h>
#include <linux/nvdev.h>

#define NVM_MSG_PREFIX "lightnvm"
#define LTOP_EMPTY -1
#define LTOP_POISON 0xD3ADB33F

#define LIGHTNVM_IOC_MAGIC 'O'
#define LIGHTNVM_IOCTL_ID _IO(LIGHTNVM_IOC_MAGIC, 0x40)

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

/* We partition the namespace of translation map into these pieces for tracking
 * in-flight addresses. */
#define NVM_INFLIGHT_PARTITIONS 8
#define NVM_INFLIGHT_TAGS 256

#define NVM_WRITE_SUCCESS  0
#define NVM_WRITE_DEFERRED 1
#define NVM_WRITE_GC_ABORT 2

#define NVM_OPT_MISC_OFFSET 15

enum ltop_flags {
	/* Update primary mapping (and init secondary mapping as a result) */
	MAP_PRIMARY	= 1 << 0,
	/* Update only shaddow mapping */
	MAP_SHADOW	= 1 << 1,
	/* Update only the relevant mapping (primary/shaddow) */
	MAP_SINGLE	= 1 << 2,
};

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
		/* number of pages that are invalid, wrt host page size */
		unsigned int nr_invalid_pages;
#define MAX_INVALID_PAGES_STORAGE 8
		/* Bitmap for invalid page intries */
		unsigned long invalid_pages[MAX_INVALID_PAGES_STORAGE];
	} ____cacheline_aligned_in_smp;

	unsigned int id;
	struct nvm_pool *pool;
	struct nvm_ap *ap;

	/* Management and GC structures */
	struct list_head list;
	struct list_head prio;

	/* Persistent data structures */
	struct page *data;
	atomic_t data_size; /* data pages inserted into data variable */
	atomic_t data_cmnt_size; /* data pages committed to stable storage */

	/* Block state handling */
	atomic_t gc_running;
	struct work_struct ws_gc;
};

/* Logical to physical mapping */
struct nvm_addr {
	sector_t addr;
	struct nvm_block *block;
	void *private;
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

	struct list_head used_list;	/* In-use blocks */
	struct list_head free_list;	/* Not used blocks i.e. released
					 *  and ready for use */
	struct list_head prio_list;	/* Blocks that may be GC'ed. */

	unsigned int id;
	/* References the physical start block */
	unsigned long phy_addr_start;
	/* References the physical end block */
	unsigned int phy_addr_end;

	unsigned int nr_blocks;		/* end_block - start_block. */
	unsigned int nr_free_blocks;	/* Number of unused blocks */

	struct nvm_block *blocks;
	struct nvmd *nvmd;

	/* Postpone issuing I/O if append point is active */
	atomic_t is_active;

	spinlock_t waiting_lock;
	struct work_struct waiting_ws;
	struct bio_list waiting_bios;

	struct bio *cur_bio;

	unsigned int gc_running;
	struct completion gc_finished;
	struct work_struct gc_ws;

	void *private;
};

/*
 * nvm_ap. ap is an append point. A pool can have 1..X append points attached.
 * An append point has a current block, that it writes to, and when its full,
 * it requests a new block, of which it continues its writes.
 *
 * one ap per pool may be reserved for pack-hints related writes.
 * In those that are not not, private is NULL.
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

	/* Private field for submodules */
	void *private;
};

struct nvm_config {
	unsigned long flags;

	unsigned int gc_time; /* GC every X microseconds */

	unsigned int t_read;
	unsigned int t_write;
	unsigned int t_erase;
};

struct nvm_inflight_addr {
	struct list_head list;
	sector_t l_addr;
	int tag;
};

struct nvm_inflight {
	spinlock_t lock;
	struct list_head addrs;
};

struct nvmd;
struct per_rq_data;

/* overridable functionality */
typedef struct nvm_addr *(*nvm_map_ltop_fn)(struct nvmd *, sector_t, int,
						struct nvm_addr *, void *);
typedef struct nvm_addr *(*nvm_lookup_ltop_fn)(struct nvmd *, sector_t);
typedef int (*nvm_write_rq_fn)(struct nvmd *, struct rq_end_io_fn *);
typedef int (*nvm_read_rq_fn)(struct nvmd *, struct rq *);
typedef void (*nvm_alloc_phys_addr_fn)(struct nvmd *, struct nvm_block *);
typedef void (*nvm_defer_rq_fn)(struct nvmd *, struct rq *, void *);
typedef void (*nvm_rq_wait_add_fn)(struct rq_list *, struct rq *, void *);
typedef int (*nvm_ioctl_fn)(struct nvmd *,
					unsigned int cmd, unsigned long arg);
typedef int (*nvm_init_fn)(struct nvmd *);
typedef void (*nvm_exit_fn)(struct nvmd *);
typedef void (*nvm_endio_fn)(struct nvmd *, struct rq *,
				struct per_rq_data *, unsigned long *delay);

typedef int (*nvm_page_special_fn)(struct nvmd *, unsigned int);

struct nvm_target_type {
	const char *name;
	unsigned int version[3];
	unsigned int per_rq_size; 

	nvm_map_ltop_fn map_ltop;

	/* lookup functions */
	nvm_lookup_ltop_fn lookup_ltop;

	/* handling of rqs */
	nvm_write_rq_fn write_rq;
	nvm_read_rq_fn read_rq;
	nvm_ioctl_fn ioctl;
	nvm_endio_fn end_rq;

	/* engine specific overrides */
	nvm_alloc_phys_addr_fn alloc_phys_addr;
	nvm_defer_rq_fn defer_rq;
	nvm_rq_wait_add_fn rq_wait_add;

	/* module specific init/teardown */
	nvm_init_fn init;
	nvm_exit_fn exit;

	/* For lightnvm internal use */
	struct list_head list;
};

/* Main structure */
struct nvmd {
	struct nvd_queue *nvq;
	uint32_t sector_size;

	struct nvm_target_type *type;

	/* Simple translation map of logical addresses to physical addresses.
	 * The logical addresses is known by the host system, while the physical
	 * addresses are used when writing to the disk block device. */
	struct nvm_addr *trans_map;
	/* also store a reverse map for garbage collection */
	struct nvm_rev_addr *rev_trans_map;
	spinlock_t rev_lock;
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

	/* Write strategy variables. Move these into each for structure for each
	 * strategy */
	atomic_t next_write_ap; /* Whenever a page is written, this is updated
				 * to point to the next write append point */
	struct workqueue_struct *krqd_wq;
	struct workqueue_struct *kgc_wq;

	spinlock_t deferred_lock;
	struct work_struct deferred_ws;
	struct bio_list deferred_bios;

	struct timer_list gc_timer;

	/* in-flight data lookup, lookup by logical address. Remember the
	 * overhead of cachelines being used. Keep it low for better cache
	 * utilization. */
	struct percpu_ida free_inflight;
	struct nvm_inflight inflight_map[NVM_INFLIGHT_PARTITIONS];
	struct nvm_inflight_addr inflight_addrs[NVM_INFLIGHT_TAGS];

	/* nvm module specific data */
	void *private;

	/* User configuration */
	struct nvm_config config;
};

struct per_rq_data {
	struct nvm_ap *ap;
	struct nvm_addr *addr;
	struct timespec start_tv;
	sector_t l_addr;

	/* Hook up for our overwritten bio fields */
	bio_end_io_t *bi_end_io;
	void *bi_private;
	struct completion *event;
	struct bio *orig_bio;
	unsigned int sync;
	unsigned int ref_put;
	struct nvm_addr *trans_map;
};

/* reg.c */
int nvm_register_target(struct nvm_target_type *t);
void nvm_unregister_target(struct nvm_target_type *t);
struct nvm_target_type *find_nvm_target_type(const char *name);

/* core.c */
/*   Helpers */
struct nvm_block *nvm_pool_get_block(struct nvm_pool *, int is_gc);
void invalidate_block_page(struct nvmd *, struct nvm_addr *);
void nvm_set_ap_cur(struct nvm_ap *, struct nvm_block *);
void nvm_defer_bio(struct nvmd *nvmd, struct bio *bio, void *private);
void nvm_bio_wait_add(struct bio_list *bl, struct bio *bio, void *p_private);
sector_t nvm_alloc_phys_addr(struct nvm_block *);
sector_t nvm_alloc_phys_addr_special(struct nvm_block *, nvm_page_special_fn);

/*   Naive implementations */
void nvm_delayed_bio_submit(struct work_struct *);
void nvm_deferred_bio_submit(struct work_struct *);
void nvm_gc_block(struct work_struct *);

/* Allocation of physical addresses from block
 * when increasing responsibility. */
struct nvm_addr *nvm_alloc_addr_from_ap(struct nvm_ap *, int is_gc);
struct nvm_addr *nvm_map_ltop_rr(struct nvmd *, sector_t l_addr, int is_gc,
				struct nvm_addr *trans_map, void *private);

/* Gets an address from nvm->trans_map and take a ref count on the blocks usage.
 * Remember to put later */
struct nvm_addr *nvm_lookup_ltop_map(struct nvmd *, sector_t l_addr,
				struct nvm_addr *l2p_map, void *private);
struct nvm_addr *nvm_lookup_ltop(struct nvmd *, sector_t l_addr);

/*   I/O bio related */
struct nvm_addr *nvm_get_trans_map(struct nvmd *nvmd, void *private);
struct request *nvm_write_init_rq(struct nvmd *, struct request *, struct nvm_addr *);
int nvm_bv_copy(struct nvm_addr *p, struct bio_vec *bv);
/* FIXME: Shorten */
int nvm_write_rq(struct nvmd *, struct request *rq, int is_gc, void *private,
		struct completion *sync, struct nvm_addr *trans_map,
		unsigned int complete_rq);
int nvm_read_rq(struct nvmd *, struct request *rq);
/* FIXME: Shorten */
void nvm_update_map(struct nvmd *nvmd, sector_t l_addr, struct nvm_addr *p,
					int is_gc, struct nvm_addr *trans_map);
/* FIXME: Shorten */
void nvm_submit_rq(struct nvmd *, struct nvm_addr *, sector_t, int rw,
		struct request *, struct request *orig_rq, struct completion *sync,
		struct nvm_addr *trans_map);
void nvm_defer_write_rq(struct nvmd *nvmd, struct request *rq, void *private);

/*   NVM device related */
void nvm_block_release(struct kref *);

/*   Block maintanence */
void nvm_pool_put_block(struct nvm_block *);
void nvm_reset_block(struct nvm_block *);

/* gc.c */
void nvm_block_erase(struct kref *);
void nvm_gc_cb(unsigned long data);
void nvm_gc_collect(struct work_struct *work);
void nvm_gc_kick(struct nvmd *nvmd);

#define nvm_for_each_pool(n, pool, i) \
		for ((i) = 0, pool = &(n)->pools[0]; \
			(i) < (n)->nr_pools; (i)++, pool = &(n)->pools[(i)])

#define nvm_for_each_ap(n, ap, i) \
		for ((i) = 0, ap = &(n)->aps[0]; \
			(i) < (n)->nr_aps; (i)++, ap = &(n)->aps[(i)])

#define pool_for_each_block(p, b, i) \
		for ((i) = 0, b = &(p)->blocks[0]; \
			(i) < (p)->nr_blocks; (i)++, b = &(p)->blocks[(i)])

static inline struct nvm_ap *get_next_ap(struct nvmd *n)
{
	return &n->aps[atomic_inc_return(&n->next_write_ap) % n->nr_aps];
}

static inline int block_is_full(struct nvm_block *block)
{
	struct nvmd *nvmd = block->pool->nvmd;
	return (block->next_page * NR_HOST_PAGES_IN_FLASH_PAGE) +
			block->next_offset == nvmd->nr_host_pages_in_blk;
}

static inline sector_t block_to_addr(struct nvm_block *block)
{
	struct nvmd *nvmd;
	BUG_ON(!block);
	nvmd = block->pool->nvmd;
	return block->id * nvmd->nr_host_pages_in_blk;
}

static inline struct nvm_pool *paddr_to_pool(struct nvmd *n, sector_t p_addr)
{
	return &n->pools[p_addr / (n->nr_pages / n->nr_pools)];
}

static inline struct nvm_ap *block_to_ap(struct nvmd *n, struct nvm_block *b)
{
	unsigned int ap_idx, div, mod;

	div = b->id / n->nr_blks_per_pool;
	mod = b->id % n->nr_blks_per_pool;
	ap_idx = div + (mod / (n->nr_blks_per_pool / n->nr_aps_per_pool));

	return &n->aps[ap_idx];
}

static inline int physical_to_slot(struct nvmd *n, sector_t phys)
{
	return (phys % (n->nr_pages_per_blk * NR_HOST_PAGES_IN_FLASH_PAGE)) /
		NR_HOST_PAGES_IN_FLASH_PAGE;
}

static inline struct per_rq_data *get_per_rq_data(struct request *rq)
{
	return blk_mq_rq_to_pdu(rq);
}

static inline struct nvm_inflight *nvm_hash_addr_to_inflight(struct nvmd *nvmd,
								sector_t l_addr)
{
	return &nvmd->inflight_map[l_addr % NVM_INFLIGHT_PARTITIONS];
}

static inline void __nvm_lock_addr(struct nvmd *nvmd, sector_t l_addr, int spin)
{
	struct nvm_inflight *inflight = nvm_hash_addr_to_inflight(nvmd, l_addr);
	struct nvm_inflight_addr *a;
	int tag = percpu_ida_alloc(&nvmd->free_inflight, __GFP_WAIT);

	BUG_ON(l_addr >= nvmd->nr_pages);

retry:
	spin_lock(&inflight->lock);

	list_for_each_entry(a, &inflight->addrs, list) {
		if (a->l_addr == l_addr) {
			spin_unlock(&inflight->lock);
			/* TODO: give up control and come back. I haven't found
			 * a good way to complete the work, when the data the
			 * complete structure is being reused */
			if (!spin)
				schedule();
			goto retry;
		}
	}

	a = &nvmd->inflight_addrs[tag];

	a->l_addr = l_addr;
	a->tag = tag;

	list_add_tail(&a->list, &inflight->addrs);
	spin_unlock(&inflight->lock);
}

static inline void nvm_lock_addr(struct nvmd *nvmd, sector_t l_addr)
{
	__nvm_lock_addr(nvmd, l_addr, 0);
}

static inline void nvm_unlock_addr(struct nvmd *nvmd, sector_t l_addr)
{
	struct nvm_inflight *inflight =
			nvm_hash_addr_to_inflight(nvmd, l_addr);
	struct nvm_inflight_addr *a = NULL;

	spin_lock(&inflight->lock);

	BUG_ON(list_empty(&inflight->addrs));

	list_for_each_entry(a, &inflight->addrs, list)
		if (a->l_addr == l_addr)
			break;

	BUG_ON(!a && a->l_addr != l_addr);

	a->l_addr = LTOP_POISON;

	list_del_init(&a->list);
	spin_unlock(&inflight->lock);
	percpu_ida_free(&nvmd->free_inflight, a->tag);
}

static inline void show_pool(struct nvm_pool *pool)
{
	struct list_head *head, *cur;
	unsigned int free_cnt = 0, used_cnt = 0, prio_cnt = 0;

	spin_lock(&pool->lock);
	list_for_each_safe(head, cur, &pool->free_list)
		free_cnt++;
	list_for_each_safe(head, cur, &pool->used_list)
		used_cnt++;
	list_for_each_safe(head, cur, &pool->prio_list)
		prio_cnt++;
	spin_unlock(&pool->lock);

	pr_err("lightnvm: P-%d F:%u U:%u P:%u", pool->id, free_cnt, used_cnt, prio_cnt);
}

static inline void show_all_pools(struct nvmd *nvmd)
{
	struct nvm_pool *pool;
	unsigned int i;

	nvm_for_each_pool(nvmd, pool, i)
		show_pool(pool);
}

#endif /* LIGHTNVM_H_ */

