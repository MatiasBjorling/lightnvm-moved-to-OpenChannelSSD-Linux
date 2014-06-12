/*
 * Copyright (C) 2014 Matias Bjørling.
 *
 * This file is released under the GPL.
 */

#ifndef VSL_H_
#define VSL_H_

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
#include <linux/openvsl.h>
#include <linux/blk-mq.h>

#define VSL_MSG_PREFIX "vsl"
#define LTOP_EMPTY -1
#define LTOP_POISON 0xD3ADB33F

#define VSL_IOC_MAGIC 'O'
#define VSL_IOCTL_ID _IO(VSL_IOC_MAGIC, 0x40)

/*
 * For now we hardcode some of the configuration for the OpenVSL device that we
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
#define VSL_INFLIGHT_PARTITIONS 8
#define VSL_INFLIGHT_TAGS 256

#define VSL_WRITE_SUCCESS  0
#define VSL_WRITE_DEFERRED 1
#define VSL_WRITE_GC_ABORT 2

#define VSL_OPT_MISC_OFFSET 15

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
	VSL_OPT_ENGINE_NONE		= 0 <<  0,
	/* Swap aware hints. Detected from block request type */
	VSL_OPT_ENGINE_SWAP		= 1 <<  0,
	/* IOCTL aware hints. Applications may submit direct hints */
	VSL_OPT_ENGINE_IOCTL	= 1 <<  1,
	/* Latency aware hints. Detected from file type or directly from app */
	VSL_OPT_ENGINE_LATENCY	= 1 <<  2,
	/* Pack aware hints. Detected from file type or directly from app */
	VSL_OPT_ENGINE_PACK	= 1 <<  3,

	/* Control accesses to append points in the host. Enable this for
	 * devices that doesn't have an internal queue that only lets one
	 * command run at a time within an append point */
	VSL_OPT_POOL_SERIALIZE	= 1 << VSL_OPT_MISC_OFFSET,
	/* Use fast/slow page access pattern */
	VSL_OPT_FAST_SLOW_PAGES	= 1 << (VSL_OPT_MISC_OFFSET+1),
	/* Disable dev waits */
	VSL_OPT_NO_WAITS	= 1 << (VSL_OPT_MISC_OFFSET+2),
};

/* Pool descriptions */
struct vsl_block {
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
	struct vsl_pool *pool;
	struct vsl_ap *ap;

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
struct vsl_addr {
	sector_t addr;
	struct vsl_block *block;
	void *private;
};

/* Physical to logical mapping */
struct vsl_rev_addr {
	sector_t addr;
	struct vsl_addr *trans_map;
};

struct vsl_pool {
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

	struct vsl_block *blocks;
	struct vsl_stor *s;

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
 * vsl_ap. ap is an append point. A pool can have 1..X append points attached.
 * An append point has a current block, that it writes to, and when its full,
 * it requests a new block, of which it continues its writes.
 *
 * one ap per pool may be reserved for pack-hints related writes.
 * In those that are not not, private is NULL.
 */
struct vsl_ap {
	spinlock_t lock;
	struct vsl_stor *parent;
	struct vsl_pool *pool;
	struct vsl_block *cur;
	struct vsl_block *gc_cur;

	/* Timings used for end_io waiting */
	unsigned long t_read;
	unsigned long t_write;
	unsigned long t_erase;

	unsigned long io_delayed;
	unsigned long io_accesses[2];

	/* Private field for submodules */
	void *private;
};

struct vsl_config {
	unsigned long flags;

	unsigned int gc_time; /* GC every X microseconds */

	unsigned int t_read;
	unsigned int t_write;
	unsigned int t_erase;
};

struct vsl_inflight_addr {
	struct list_head list;
	sector_t l_addr;
	int tag;
};

struct vsl_inflight {
	spinlock_t lock;
	struct list_head addrs;
};

struct vsl_stor;
struct per_rq_data;

/* overridable functionality */
typedef struct vsl_addr *(*vsl_map_ltop_fn)(struct vsl_stor *, sector_t, int,
						struct vsl_addr *, void *);
typedef struct vsl_addr *(*vsl_lookup_ltop_fn)(struct vsl_stor *, sector_t);
typedef int (*vsl_write_rq_fn)(struct vsl_stor *, struct request *);
typedef int (*vsl_read_rq_fn)(struct vsl_stor *, struct request *);
typedef void (*vsl_alloc_phys_addr_fn)(struct vsl_stor *, struct vsl_block *);
typedef int (*vsl_ioctl_fn)(struct vsl_stor *,
					unsigned int cmd, unsigned long arg);
typedef int (*vsl_init_fn)(struct vsl_stor *);
typedef void (*vsl_exit_fn)(struct vsl_stor *);
typedef void (*vsl_endio_fn)(struct vsl_stor *, struct request *,
				struct per_rq_data *, unsigned long *delay);

typedef int (*vsl_page_special_fn)(struct vsl_stor *, unsigned int);

struct vsl_target_type {
	const char *name;
	unsigned int version[3];
	unsigned int per_rq_size; 

	vsl_map_ltop_fn map_ltop;

	/* lookup functions */
	vsl_lookup_ltop_fn lookup_ltop;

	/* handling of rqs */
	vsl_write_rq_fn write_rq;
	vsl_read_rq_fn read_rq;
	vsl_ioctl_fn ioctl;
	vsl_endio_fn end_rq;

	/* engine specific overrides */
	vsl_alloc_phys_addr_fn alloc_phys_addr;

	/* module specific init/teardown */
	vsl_init_fn init;
	vsl_exit_fn exit;

	/* For lightnvm internal use */
	struct list_head list;
};

/* Main structure */
struct vsl_stor {
	struct openvsl_dev *dev;
	uint32_t sector_size;

	struct vsl_target_type *type;

	/* Simple translation map of logical addresses to physical addresses.
	 * The logical addresses is known by the host system, while the physical
	 * addresses are used when writing to the disk block device. */
	struct vsl_addr *trans_map;
	/* also store a reverse map for garbage collection */
	struct vsl_rev_addr *rev_trans_map;
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
	struct vsl_pool *pools;

	/* Append points */
	struct vsl_ap *aps;

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
	struct vsl_inflight inflight_map[VSL_INFLIGHT_PARTITIONS];
	struct vsl_inflight_addr inflight_addrs[VSL_INFLIGHT_TAGS];

	/* nvm module specific data */
	void *private;

	/* User configuration */
	struct vsl_config config;

	unsigned int per_rq_offset;
};

struct per_rq_data {
	struct vsl_ap *ap;
	struct vsl_addr *addr;
	struct timespec start_tv;
	sector_t l_addr;

	/* Hook up for our overwritten bio fields */
	rq_end_io_fn *end_io;
	void *end_io_data;
	struct completion *event;
	struct request *orig_rq;
	unsigned int sync;
	unsigned int ref_put;
	struct vsl_addr *trans_map;
};

/* reg.c */
int vsl_register_target(struct vsl_target_type *t);
void vsl_unregister_target(struct vsl_target_type *t);
struct vsl_target_type *find_vsl_target_type(const char *name);

/* core.c */
/*   Helpers */
struct vsl_block *vsl_pool_get_block(struct vsl_pool *, int is_gc);
void invalidate_block_page(struct vsl_stor *, struct vsl_addr *);
void vsl_set_ap_cur(struct vsl_ap *, struct vsl_block *);
sector_t vsl_alloc_phys_addr(struct vsl_block *);
sector_t vsl_alloc_phys_addr_special(struct vsl_block *, vsl_page_special_fn);

/*   Naive implementations */
void vsl_delayed_bio_submit(struct work_struct *);
void vsl_deferred_bio_submit(struct work_struct *);
void vsl_gc_block(struct work_struct *);

/* Allocation of physical addresses from block
 * when increasing responsibility. */
struct vsl_addr *vsl_alloc_addr_from_ap(struct vsl_ap *, int is_gc);
struct vsl_addr *vsl_map_ltop_rr(struct vsl_stor *, sector_t l_addr, int is_gc,
				struct vsl_addr *trans_map, void *private);

/* Gets an address from nvm->trans_map and take a ref count on the blocks usage.
 * Remember to put later */
struct vsl_addr *vsl_lookup_ltop_map(struct vsl_stor *, sector_t l_addr,
				struct vsl_addr *l2p_map, void *private);
struct vsl_addr *vsl_lookup_ltop(struct vsl_stor *, sector_t l_addr);

/*   I/O bio related */
struct vsl_addr *vsl_get_trans_map(struct vsl_stor *, void *private);
struct request *vsl_write_init_rq(struct vsl_stor *, struct request *, struct vsl_addr *);
/* FIXME: Shorten */
int __vsl_write_rq(struct vsl_stor *, struct request *rq, int is_gc, void *private,
		struct completion *sync, struct vsl_addr *trans_map,
		unsigned int complete_rq);
int vsl_write_rq(struct vsl_stor *, struct request *rq);
int vsl_read_rq(struct vsl_stor *, struct request *rq);
/* FIXME: Shorten */
void vsl_update_map(struct vsl_stor *s, sector_t l_addr, struct vsl_addr *p,
					int is_gc, struct vsl_addr *trans_map);
/* FIXME: Shorten */
void vsl_submit_rq(struct vsl_stor *, struct vsl_addr *, sector_t, int rw,
		struct request *, struct request *orig_rq, struct completion *sync,
		struct vsl_addr *trans_map);
void vsl_defer_write_rq(struct vsl_stor *s, struct request *rq, void *private);

/*   VSL device related */
void vsl_block_release(struct kref *);

/*   Block maintanence */
void vsl_pool_put_block(struct vsl_block *);
void vsl_reset_block(struct vsl_block *);

/* gc.c */
void vsl_block_erase(struct kref *);
void vsl_gc_cb(unsigned long data);
void vsl_gc_collect(struct work_struct *work);
void vsl_gc_kick(struct vsl_stor *s);

#define vsl_for_each_pool(n, pool, i) \
		for ((i) = 0, pool = &(n)->pools[0]; \
			(i) < (n)->nr_pools; (i)++, pool = &(n)->pools[(i)])

#define vsl_for_each_ap(n, ap, i) \
		for ((i) = 0, ap = &(n)->aps[0]; \
			(i) < (n)->nr_aps; (i)++, ap = &(n)->aps[(i)])

#define pool_for_each_block(p, b, i) \
		for ((i) = 0, b = &(p)->blocks[0]; \
			(i) < (p)->nr_blocks; (i)++, b = &(p)->blocks[(i)])

static inline struct vsl_ap *get_next_ap(struct vsl_stor *s)
{
	return &s->aps[atomic_inc_return(&s->next_write_ap) % s->nr_aps];
}

static inline int block_is_full(struct vsl_block *block)
{
	struct vsl_stor *s = block->pool->s;
	return (block->next_page * NR_HOST_PAGES_IN_FLASH_PAGE) +
			block->next_offset == s->nr_host_pages_in_blk;
}

static inline sector_t block_to_addr(struct vsl_block *block)
{
	struct vsl_stor *s;
	BUG_ON(!block);
	s = block->pool->s;
	return block->id * s->nr_host_pages_in_blk;
}

static inline struct vsl_pool *paddr_to_pool(struct vsl_stor *s, sector_t p_addr)
{
	return &s->pools[p_addr / (s->nr_pages / s->nr_pools)];
}

static inline struct vsl_ap *block_to_ap(struct vsl_stor *s, struct vsl_block *b)
{
	unsigned int ap_idx, div, mod;

	div = b->id / s->nr_blks_per_pool;
	mod = b->id % s->nr_blks_per_pool;
	ap_idx = div + (mod / (s->nr_blks_per_pool / s->nr_aps_per_pool));

	return &s->aps[ap_idx];
}

static inline int physical_to_slot(struct vsl_stor *s, sector_t phys)
{
	return (phys % (s->nr_pages_per_blk * NR_HOST_PAGES_IN_FLASH_PAGE)) /
		NR_HOST_PAGES_IN_FLASH_PAGE;
}

static inline struct per_rq_data *get_per_rq_data(struct openvsl_dev *dev,
							struct request *rq)
{
	return (void *)blk_mq_rq_to_pdu(rq) + dev->per_rq_offset;
}

static inline struct vsl_inflight *vsl_hash_addr_to_inflight(struct vsl_stor *s,
								sector_t l_addr)
{
	return &s->inflight_map[l_addr % VSL_INFLIGHT_PARTITIONS];
}

static inline void __vsl_lock_addr(struct vsl_stor *s, sector_t l_addr, int spin)
{
	struct vsl_inflight *inflight = vsl_hash_addr_to_inflight(s, l_addr);
	struct vsl_inflight_addr *a;
	int tag = percpu_ida_alloc(&s->free_inflight, __GFP_WAIT);

	BUG_ON(l_addr >= s->nr_pages);

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

	a = &s->inflight_addrs[tag];

	a->l_addr = l_addr;
	a->tag = tag;

	list_add_tail(&a->list, &inflight->addrs);
	spin_unlock(&inflight->lock);
}

static inline void vsl_lock_addr(struct vsl_stor *s, sector_t l_addr)
{
	__vsl_lock_addr(s, l_addr, 0);
}

static inline void vsl_unlock_addr(struct vsl_stor *s, sector_t l_addr)
{
	struct vsl_inflight *inflight =
			vsl_hash_addr_to_inflight(s, l_addr);
	struct vsl_inflight_addr *a = NULL;

	spin_lock(&inflight->lock);

	BUG_ON(list_empty(&inflight->addrs));

	list_for_each_entry(a, &inflight->addrs, list)
		if (a->l_addr == l_addr)
			break;

	BUG_ON(!a && a->l_addr != l_addr);

	a->l_addr = LTOP_POISON;

	list_del_init(&a->list);
	spin_unlock(&inflight->lock);
	percpu_ida_free(&s->free_inflight, a->tag);
}

static inline void show_pool(struct vsl_pool *pool)
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

static inline void show_all_pools(struct vsl_stor *s)
{
	struct vsl_pool *pool;
	unsigned int i;

	vsl_for_each_pool(s, pool, i)
		show_pool(pool);
}

#endif /* VSL_H_ */

