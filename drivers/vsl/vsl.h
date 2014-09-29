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
#include <linux/slab.h>

#ifdef VSL_DEBUG
/*Wrap BUG_ON to allow additional checks in debug mode without
 impacting production performance*/
#define VSL_ASSERT(c) BUG_ON( (c) == 0 )
#else
#define VSL_ASSERT(c)
#endif //VSL_DEBUG

#define VSL_MSG_PREFIX "vsl"
#define LTOP_EMPTY -1
#define LTOP_POISON 0xD3ADB33F

/*
 * For now we hardcode some of the configuration for the OpenVSL device that we
 * have. In the future this should be made configurable.
 *
 * Configuration:
 * EXPOSED_PAGE_SIZE - the page size of which we tell the layers above the
 * driver to issue. This usually is 512 bytes for 4K for simplivity.
 */

#define EXPOSED_PAGE_SIZE 4096

/* We currently assume that we the lightnvm device is accepting data in 512
 * bytes chunks. This should be set to the smallest command size available for a
 * given device.
 */
#define NR_PHY_IN_LOG (EXPOSED_PAGE_SIZE / 512)

/* We partition the namespace of translation map into these pieces for tracking
 * in-flight addresses. */
#define VSL_INFLIGHT_PARTITIONS 8
#define VSL_INFLIGHT_TAGS 256

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
		/* points to the next writable page within a block */
		unsigned int next_page;
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
	atomic_t data_size; /* data pages inserted into data variable */
	atomic_t data_cmnt_size; /* data pages committed to stable storage */

	/* Block state handling */
	atomic_t gc_running;
	struct work_struct ws_gc;
	struct work_struct ws_eio;
};

/* Logical to physical mapping */
struct vsl_addr {
	sector_t addr;
	struct vsl_block *block;
};

/* Physical to logical mapping */
struct vsl_rev_addr {
	sector_t addr;
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

struct vsl_inflight_request {
	struct list_head list;
	sector_t l_start;
	sector_t l_end;
	int tag;
};

struct vsl_inflight {
	spinlock_t lock;
	struct list_head reqs;
};

struct vsl_stor;
struct per_rq_data;
struct vsl_block;
struct vsl_pool;

/* overridable functionality */
typedef struct vsl_addr *(*vsl_lookup_ltop_fn)(struct vsl_stor *, sector_t);
typedef struct vsl_addr *(*vsl_map_ltop_page_fn)(struct vsl_stor *, sector_t,
						int);
typedef struct vsl_block *(*vsl_map_ltop_block_fn)(struct vsl_stor *, sector_t,
						int);
typedef int (*vsl_write_rq_fn)(struct vsl_stor *, struct request *);
typedef int (*vsl_read_rq_fn)(struct vsl_stor *, struct request *);
typedef void (*vsl_alloc_phys_addr_fn)(struct vsl_stor *, struct vsl_block *);
typedef struct vsl_block *(*vsl_pool_get_blk_fn)(struct vsl_pool *pool,
						int is_gc);
typedef void (*vsl_pool_put_blk_fn)(struct vsl_block *block);
typedef int (*vsl_ioctl_fn)(struct vsl_stor *,
					unsigned int cmd, unsigned long arg);
typedef int (*vsl_init_fn)(struct vsl_stor *);
typedef void (*vsl_exit_fn)(struct vsl_stor *);
typedef void (*vsl_endio_fn)(struct vsl_stor *, struct request *,
				struct per_rq_data *, unsigned long *delay);

struct vsl_target_type {
	const char *name;
	unsigned int version[3];
	unsigned int per_rq_size;

	/* lookup functions */
	vsl_lookup_ltop_fn lookup_ltop;

	/* handling of rqs */
	vsl_write_rq_fn write_rq;
	vsl_read_rq_fn read_rq;
	vsl_ioctl_fn ioctl;
	vsl_endio_fn end_rq;

	/* engine-specific overrides */
	vsl_alloc_phys_addr_fn alloc_phys_addr;
	vsl_pool_get_blk_fn pool_get_blk;
	vsl_pool_put_blk_fn pool_put_blk;
	vsl_map_ltop_page_fn map_page;
	vsl_map_ltop_block_fn map_block;

	/* module specific init/teardown */
	vsl_init_fn init;
	vsl_exit_fn exit;

	/* For lightnvm internal use */
	struct list_head list;
};

struct kv_entry;

struct vslkv_tbl {
	u8 bucket_len;
	u64 tbl_len;
	struct kv_entry *entries;
	spinlock_t lock;
};

struct vslkv_inflight {
	struct kmem_cache *entry_pool;
	spinlock_t lock;
	struct list_head list;
};

struct vslkv {
	struct vslkv_tbl tbl;
	struct vslkv_inflight inflight;
};

/* Main structure */
struct vsl_stor {
	struct vsl_dev *dev;
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

	/* Frequently used config variables */
	int nr_pools;
	int nr_blks_per_pool;
	int nr_pages_per_blk;
	int nr_aps;
	int nr_aps_per_pool;
	unsigned gran_blk;
	unsigned gran_read;
	unsigned gran_write;

	/* Calculated values */
	unsigned long nr_pages;

	unsigned int next_collect_pool;

	/* Write strategy variables. Move these into each for structure for each
	 * strategy */
	atomic_t next_write_ap; /* Whenever a page is written, this is updated
				 * to point to the next write append point */
	struct workqueue_struct *krqd_wq;
	struct workqueue_struct *kgc_wq;

	struct timer_list gc_timer;

	/* in-flight data lookup, lookup by logical address. Remember the
	 * overhead of cachelines being used. Keep it low for better cache
	 * utilization. */
	struct percpu_ida free_inflight;
	struct vsl_inflight inflight_map[VSL_INFLIGHT_PARTITIONS];
	struct vsl_inflight_request inflight_addrs[VSL_INFLIGHT_TAGS];

	/* nvm module specific data */
	void *private;

	/* User configuration */
	struct vsl_config config;

	unsigned int per_rq_offset;

	struct vslkv kv;

	int internal_bad_blocks;


	spinlock_t	disk_lock;
	struct radix_tree_root disk_tree;
};

struct per_rq_data_vsl {
	struct vsl_dev *dev;
};

enum {
	VSL_RQ_NONE = 0,
	VSL_RQ_GC = 1,
};

struct per_rq_data {
	struct vsl_ap *ap;
	struct vsl_addr *addr;
	sector_t l_addr;
	unsigned int flags;
};

/* reg.c */
int vsl_register_target(struct vsl_target_type *t);
void vsl_unregister_target(struct vsl_target_type *t);
struct vsl_target_type *find_vsl_target_type(const char *name);

/* core.c */
/*   Helpers */
void __invalidate_block_page(struct vsl_stor *, struct vsl_addr *);
void invalidate_block_page(struct vsl_stor *, struct vsl_addr *);
void vsl_set_ap_cur(struct vsl_ap *, struct vsl_block *);
sector_t vsl_alloc_phys_addr(struct vsl_block *);

/*   Naive implementations */
void vsl_delayed_bio_submit(struct work_struct *);
void vsl_deferred_bio_submit(struct work_struct *);
void vsl_gc_block(struct work_struct *);
void vsl_gc_recycle_block(struct work_struct *);

/* Allocation of physical addresses from block
 * when increasing responsibility. */
struct vsl_addr *vsl_alloc_addr_from_ap(struct vsl_ap *, int is_gc);

/*   I/O request related */
/* FIXME: Shorten */
int vsl_write_rq(struct vsl_stor *, struct request *);
int __vsl_write_rq(struct vsl_stor *, struct request *, int);
int vsl_read_rq(struct vsl_stor *, struct request *rq);

void vsl_update_map(struct vsl_stor *s, sector_t l_addr, struct vsl_addr *p, int is_gc);
void vsl_setup_rq(struct vsl_stor *, struct request *, struct vsl_addr *, sector_t, unsigned int flags);

/*   VSL device related */
void vsl_block_release(struct kref *);

/*   Block maintanence */
void vsl_reset_block(struct vsl_block *);

void vsl_endio(struct vsl_dev *, struct request *, int);

/* gc.c */
void vsl_block_erase(struct kref *);
void vsl_gc_cb(unsigned long data);
void vsl_gc_collect(struct work_struct *work);
void vsl_gc_kick(struct vsl_stor *s);

/* vsltgt.c */
struct vsl_block *vsl_pool_get_block(struct vsl_pool *, int is_gc);

/* vslkv.c */
int vslkv_init(struct vsl_stor *s, unsigned long size);
void vslkv_exit(struct vsl_stor *s);
int vslkv_unpack(struct vsl_dev *dev, struct openvsl_cmd_kv __user *ucmd);
void vsl_pool_put_block(struct vsl_block *);


#define vsl_for_each_pool(n, pool, i) \
		for ((i) = 0, pool = &(n)->pools[0]; \
			(i) < (n)->nr_pools; (i)++, pool = &(n)->pools[(i)])

#define vsl_for_each_ap(n, ap, i) \
		for ((i) = 0, ap = &(n)->aps[0]; \
			(i) < (n)->nr_aps; (i)++, ap = &(n)->aps[(i)])

#define pool_for_each_block(p, b, i) \
		for ((i) = 0, b = &(p)->blocks[0]; \
			(i) < (p)->nr_blocks; (i)++, b = &(p)->blocks[(i)])

#define block_for_each_page(b, p) \
	for((p)->addr = block_to_addr((b)), (p)->block = (b); \
		(p)->addr < block_to_addr((b)) \
			+ (b)->pool->s->nr_pages_per_blk; \
		(p)->addr++)

static inline struct vsl_ap *get_next_ap(struct vsl_stor *s)
{
	return &s->aps[atomic_inc_return(&s->next_write_ap) % s->nr_aps];
}

static inline int block_is_full(struct vsl_block *block)
{
	struct vsl_stor *s = block->pool->s;

	return block->next_page == s->nr_pages_per_blk;
}

static inline sector_t block_to_addr(struct vsl_block *block)
{
	struct vsl_stor *s = block->pool->s;

	return block->id * s->nr_pages_per_blk;
}

static inline struct vsl_pool *paddr_to_pool(struct vsl_stor *s,
							sector_t p_addr)
{
	return &s->pools[p_addr / (s->nr_pages / s->nr_pools)];
}

static inline struct vsl_ap *block_to_ap(struct vsl_stor *s,
							struct vsl_block *b)
{
	unsigned int ap_idx, div, mod;

	div = b->id / s->nr_blks_per_pool;
	mod = b->id % s->nr_blks_per_pool;
	ap_idx = div + (mod / (s->nr_blks_per_pool / s->nr_aps_per_pool));

	return &s->aps[ap_idx];
}

static inline int physical_to_slot(struct vsl_stor *s, sector_t phys)
{
	return phys % s->nr_pages_per_blk;
}

static inline void *get_per_rq_data(struct vsl_dev *dev, struct request *rq)
{
	BUG_ON(!dev);
	return blk_mq_rq_to_pdu(rq) + dev->drv_cmd_size;
}

static inline struct vsl_inflight *vsl_laddr_to_inflight(struct vsl_stor *s,
							sector_t l_addr)
{
	return &s->inflight_map[l_addr % VSL_INFLIGHT_PARTITIONS ];
}

static inline int request_equals(struct vsl_inflight_request *r,
			sector_t laddr_start, sector_t laddr_end)
{
	return (r->l_end == laddr_end && r->l_start == laddr_start);
}

static inline int request_intersects(struct vsl_inflight_request *r,
				sector_t laddr_start, sector_t laddr_end)
{
	return (laddr_end >= r->l_start && laddr_end <= r->l_end) &&
		(laddr_start >= r->l_start && laddr_start <= r->l_end);
}

/*TODO: make compatible with multi-block requests*/
static inline void __vsl_lock_laddr_range(struct vsl_stor *s, int spin,
				sector_t laddr_start, unsigned nsectors)
{
	struct vsl_inflight *inflight;
	struct vsl_inflight_request *r;
	sector_t laddr_end = laddr_start + nsectors - 1;
	int tag;
	unsigned long flags;

	VSL_ASSERT(nsectors >= 1);
	BUG_ON(laddr_end >= s->nr_pages);
	BUG_ON(nsectors > s->nr_pages_per_blk); /*FIXME Not yet supported*/

	inflight = vsl_laddr_to_inflight(s, laddr_start);
	tag = percpu_ida_alloc(&s->free_inflight, __GFP_WAIT);

retry:
	spin_lock_irqsave(&inflight->lock, flags);

	list_for_each_entry(r, &inflight->reqs, list) {
		if (request_intersects(r, laddr_start, laddr_end)) {
			/*existing, overlapping request, come back later*/
			spin_unlock_irqrestore(&inflight->lock, flags);
			if (!spin)
				schedule();
			goto retry;
		}
	}

	r = &s->inflight_addrs[tag];

	r->l_start = laddr_start;
	r->l_end = laddr_end;
	r->tag = tag;

	list_add_tail(&r->list, &inflight->reqs);
	spin_unlock_irqrestore(&inflight->lock, flags);
}

static inline void vsl_lock_laddr_range(struct vsl_stor *s, sector_t laddr_start,
					unsigned int nsectors)
{
	return __vsl_lock_laddr_range(s, 0, laddr_start, nsectors);
}

static inline void vsl_unlock_laddr_range(struct vsl_stor *s,
					sector_t laddr_start,
					unsigned int nsectors)
{
	struct vsl_inflight *inflight = vsl_laddr_to_inflight(s, laddr_start);
	struct vsl_inflight_request *r = NULL;
	sector_t laddr_end = laddr_start + nsectors - 1;
	unsigned long flags;

	VSL_ASSERT(nsectors >= 1);
	VSL_ASSERT(laddr_end >= laddr_start);

	spin_lock_irqsave(&inflight->lock, flags);
	BUG_ON(list_empty(&inflight->reqs));

	list_for_each_entry(r, &inflight->reqs, list)
		if (request_equals(r, laddr_start, laddr_end))
			break;

	BUG_ON(!r || !request_equals(r, laddr_start, laddr_end));

	r->l_start = r->l_end = LTOP_POISON;

	list_del_init(&r->list);
	spin_unlock_irqrestore(&inflight->lock, flags);
	percpu_ida_free(&s->free_inflight, r->tag);
}

static inline void __show_pool(struct vsl_pool *pool)
{
	struct list_head *head, *cur;
	unsigned int free_cnt = 0, used_cnt = 0, prio_cnt = 0;

	VSL_ASSERT(spin_is_locked(&pool->lock));

	list_for_each_safe(head, cur, &pool->free_list)
		free_cnt++;
	list_for_each_safe(head, cur, &pool->used_list)
		used_cnt++;
	list_for_each_safe(head, cur, &pool->prio_list)
		prio_cnt++;

	pr_err("lightnvm: P-%d F:%u U:%u P:%u",
					pool->id, free_cnt, used_cnt, prio_cnt);
}

static inline void show_pool(struct vsl_pool *pool)
{
	spin_lock(&pool->lock);
	__show_pool(pool);
	spin_unlock(&pool->lock);
}

static inline void show_all_pools(struct vsl_stor *s)
{
	struct vsl_pool *pool;
	unsigned int i;

	vsl_for_each_pool(s, pool, i)
		show_pool(pool);
}

#endif /* VSL_H_ */

