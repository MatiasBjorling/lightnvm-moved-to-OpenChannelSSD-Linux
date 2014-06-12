/*
 * Copyright (C) 2014 Matias Bjørling.
 *
 * Todo
 *
 * - Implement fetching of bad pages from flash
 * - configurable sector size
 * - handle case of in-page bv_offset (currently hidden assumption of offset=0,
 *   and bv_len spans entire page)
 *
 * Optimization possibilities
 * - Move ap_next_write into a conconcurrency friendly data structure. Could be
 *   handled by more intelligent map_ltop function.
 * - Implement per-cpu vsl_block data structure ownership. Removes need
 *   for taking lock on block next_write_id function. I.e. page allocation
 *   becomes nearly lockless, with occasionally movement of blocks on
 *   vsl_block lists.
 */

#include <linux/blk-mq.h>
#include <linux/list.h>
#include <linux/sem.h>
#include <linux/openvsl.h>
#include "vsl.h"

/* Defaults
 * Number of append points per pool. We assume that accesses within a pool is
 * serial (NAND flash/PCM/etc.)
 */
#define APS_PER_POOL 1

/* If enabled, we delay requests on each ap to run serialized. */
#define SERIALIZE_POOL_ACCESS 0

/* Sleep timings before simulating device specific storage (in us) */
#define TIMING_READ 25
#define TIMING_WRITE 500
#define TIMING_ERASE 1500

/* Run GC every X seconds */
#define GC_TIME 10

/* Minimum pages needed within a pool */
#define MIN_POOL_PAGES 16

static struct kmem_cache *_addr_cache;

static LIST_HEAD(_targets);
static DECLARE_RWSEM(_lock);

inline struct vsl_target_type *find_vsl_target_type(const char *name)
{
	struct vsl_target_type *t;

	list_for_each_entry(t, &_targets, list)
		if (!strcmp(name, t->name))
			return t;

	return NULL;
}

int vsl_register_target(struct vsl_target_type *t)
{
	int ret = 0;

	down_write(&_lock);
	if (find_vsl_target_type(t->name))
		ret = -EEXIST;
	else
		list_add(&t->list, &_targets);
	up_write(&_lock);
	return ret;
}

void vsl_unregister_target(struct vsl_target_type *t)
{
	if (!t)
		return;

	down_write(&_lock);
	list_del(&t->list);
	up_write(&_lock);
}

static int vsl_queue_rq(struct blk_mq_hw_ctx *hctx, struct request *rq)
{
	struct vsl_stor *s = hctx->private;

	if (blk_rq_pos(rq) / NR_PHY_IN_LOG >= s->nr_pages) {
		pr_err("Illegal vsl address: %ld",
						blk_rq_pos(rq) / NR_PHY_IN_LOG);
		return BLK_MQ_RQ_QUEUE_ERROR;
	};

	/* limited currently to 4k write IOs */
	if (rq_data_dir(rq) == WRITE) {
		return s->type->write_rq(s, rq);
	} else
		return s->type->read_rq(s, rq);
}

void vsl_end_io(struct request *rq, int error)
{
	blk_mq_end_io(rq, error);
}

void vsl_complete_request(struct request *rq)
{
	blk_mq_complete_request(rq);
}

static int vsl_pool_init(struct vsl_stor *s, struct vsl_dev *dev)
{
	struct vsl_pool *pool;
	struct vsl_block *block;
	struct vsl_ap *ap;
	int i, j;

	spin_lock_init(&s->deferred_lock);
	spin_lock_init(&s->rev_lock);
	INIT_WORK(&s->deferred_ws, vsl_deferred_bio_submit);
	bio_list_init(&s->deferred_bios);

	s->pools = kzalloc(sizeof(struct vsl_pool) * s->nr_pools,
								GFP_KERNEL);
	if (!s->pools)
		goto err_pool;

	vsl_for_each_pool(s, pool, i) {
		spin_lock_init(&pool->lock);
		spin_lock_init(&pool->waiting_lock);

		init_completion(&pool->gc_finished);

		INIT_WORK(&pool->gc_ws, vsl_gc_collect);
		INIT_WORK(&pool->waiting_ws, vsl_delayed_bio_submit);

		INIT_LIST_HEAD(&pool->free_list);
		INIT_LIST_HEAD(&pool->used_list);
		INIT_LIST_HEAD(&pool->prio_list);

		pool->id = i;
		pool->s = s;
		pool->phy_addr_start = i * s->nr_blks_per_pool;
		pool->phy_addr_end = (i + 1) * s->nr_blks_per_pool - 1;
		pool->nr_free_blocks = pool->nr_blocks =
				pool->phy_addr_end - pool->phy_addr_start + 1;
		bio_list_init(&pool->waiting_bios);
		atomic_set(&pool->is_active, 0);

		pool->blocks = kzalloc(sizeof(struct vsl_block) *
						pool->nr_blocks, GFP_KERNEL);
		if (!pool->blocks)
			goto err_blocks;

		spin_lock(&pool->lock);
		pool_for_each_block(pool, block, j) {
			spin_lock_init(&block->lock);
			atomic_set(&block->gc_running, 0);
			INIT_LIST_HEAD(&block->list);
			INIT_LIST_HEAD(&block->prio);

			block->pool = pool;
			block->id = (i * s->nr_blks_per_pool) + j;

			list_add_tail(&block->list, &pool->free_list);
			INIT_WORK(&block->ws_gc, vsl_gc_block);
		}
		spin_unlock(&pool->lock);
}

	s->nr_aps = s->nr_aps_per_pool * s->nr_pools;
	s->aps = kzalloc(sizeof(struct vsl_ap) * s->nr_aps, GFP_KERNEL);
	if (!s->aps)
		goto err_blocks;

	vsl_for_each_ap(s, ap, i) {
		spin_lock_init(&ap->lock);
		ap->parent = s;
		ap->pool = &s->pools[i / s->nr_aps_per_pool];

		block = vsl_pool_get_block(ap->pool, 0);
		vsl_set_ap_cur(ap, block);
		/* Emergency gc block */
		block = vsl_pool_get_block(ap->pool, 1);
		ap->gc_cur = block;

		ap->t_read = s->config.t_read;
		ap->t_write = s->config.t_write;
		ap->t_erase = s->config.t_erase;
	}

	/* we make room for each pool context. */
	s->krqd_wq = alloc_workqueue("knvm-work", WQ_MEM_RECLAIM|WQ_UNBOUND,
						s->nr_pools);
	if (!s->krqd_wq) {
		pr_err("Couldn't start knvm-work");
		goto err_blocks;
	}

	s->kgc_wq = alloc_workqueue("knvm-gc", WQ_MEM_RECLAIM, 1);
	if (!s->kgc_wq) {
		pr_err("Couldn't start knvm-gc");
		goto err_wq;
	}

	return 0;
err_wq:
	destroy_workqueue(s->krqd_wq);
err_blocks:
	vsl_for_each_pool(s, pool, i) {
		if (!pool->blocks)
			break;
		kfree(pool->blocks);
	}
	kfree(s->pools);
err_pool:
	pr_err("lightnvm: cannot allocate lightnvm data structures");
	return -ENOMEM;
}

static int vsl_stor_init(struct vsl_dev *dev, struct vsl_stor *s)
{
	int i;
	unsigned int order;

	s->trans_map = vmalloc(sizeof(struct vsl_addr) * s->nr_pages);
	if (!s->trans_map)
		return -ENOMEM;
	memset(s->trans_map, 0, sizeof(struct vsl_addr) * s->nr_pages);

	s->rev_trans_map = vmalloc(sizeof(struct vsl_rev_addr)
							* s->nr_pages);
	if (!s->rev_trans_map)
		goto err_rev_trans_map;

	for (i = 0; i < s->nr_pages; i++) {
		struct vsl_addr *p = &s->trans_map[i];
		struct vsl_rev_addr *r = &s->rev_trans_map[i];

		p->addr = LTOP_EMPTY;

		r->addr = 0xDEADBEEF;
		r->trans_map = NULL;
	}

	s->page_pool = mempool_create_page_pool(MIN_POOL_PAGES, 0);
	if (!s->page_pool)
		goto err_dev_lookup;

	s->addr_pool = mempool_create_slab_pool(64, _addr_cache);
	if (!s->addr_pool)
		goto err_page_pool;

	order = ffs(s->nr_host_pages_in_blk) - 1;
	s->block_page_pool = mempool_create_page_pool(s->nr_aps, order);
	if (!s->block_page_pool)
		goto err_addr_pool;

	/*if (bdev_physical_block_size(s->dev->bdev) > EXPOSED_PAGE_SIZE) {
		pr_err("lightnvm: bad sector size.");
		goto err_block_page_pool;
	}*/
	s->sector_size = EXPOSED_PAGE_SIZE;

	/* inflight maintainence */
	percpu_ida_init(&s->free_inflight, VSL_INFLIGHT_TAGS);

	for (i = 0; i < VSL_INFLIGHT_PARTITIONS; i++) {
		spin_lock_init(&s->inflight_map[i].lock);
		INIT_LIST_HEAD(&s->inflight_map[i].addrs);
	}

	/* simple round-robin strategy */
	atomic_set(&s->next_write_ap, -1);

	s->dev = dev;
	dev->stor = s;

	/* Initialize pools. */
	vsl_pool_init(s, dev);

	if (s->type->init && s->type->init(s))
		goto err_block_page_pool;

	/* FIXME: Clean up pool init on failure. */
	setup_timer(&s->gc_timer, vsl_gc_cb, (unsigned long)s);
	mod_timer(&s->gc_timer, jiffies + msecs_to_jiffies(1000));

	return 0;
err_block_page_pool:
	mempool_destroy(s->block_page_pool);
err_addr_pool:
	mempool_destroy(s->addr_pool);
err_page_pool:
	mempool_destroy(s->page_pool);
err_dev_lookup:
	vfree(s->rev_trans_map);
err_rev_trans_map:
	vfree(s->trans_map);
	return -ENOMEM;
}

#define VSL_TARGET_TYPE "rrpc"
#define VSL_NUM_POOLS 8
#define VSL_NUM_BLOCKS 256
#define VSL_NUM_PAGES 256

/* none target type, round robin, page-based FTL, and cost-based GC */
static struct vsl_target_type vsl_target_rrpc = {
	.name			= "rrpc",
	.version		= {1, 0, 0},
	.lookup_ltop	= vsl_lookup_ltop,
	.map_ltop	= vsl_map_ltop_rr,
	.write_rq	= vsl_write_rq,
	.read_rq	= vsl_read_rq,
};

struct vsl_dev *vsl_alloc()
{
	return kmalloc(sizeof(struct vsl_dev), GFP_KERNEL);
}

void vsl_free(struct vsl_dev *dev)
{
	kfree(dev);
}

int vsl_init(struct vsl_dev *dev)
{
	struct vsl_stor *s;

	if (!dev->ops.identify || !dev->ops.queue_rq || !dev->ops.timeout)
		return -EINVAL;

	_addr_cache = kmem_cache_create("vsl_addr_cache",
				sizeof(struct vsl_addr), 0, 0, NULL);
	if (!_addr_cache)
		return -ENOMEM;

	vsl_register_target(&vsl_target_rrpc);

	s = kzalloc(sizeof(struct vsl_stor), GFP_KERNEL);
	if (!s) {
		kmem_cache_destroy(_addr_cache);
		return -ENOMEM;
	}

	/* hardcode initialization values until user-space util is avail. */
	s->type = &vsl_target_rrpc;
	if (!s->type) {
		pr_err("vsl: %s doesn't exist.", VSL_TARGET_TYPE);
		goto err_map;
	}

	s->nr_pools = VSL_NUM_POOLS;
	s->nr_blks_per_pool = VSL_NUM_BLOCKS;
	s->nr_pages_per_blk = VSL_NUM_PAGES;

	/* Optional */
	s->nr_aps_per_pool = APS_PER_POOL;
	/* s->config.flags = VSL_OPT_* */
	s->config.gc_time = GC_TIME;
	s->config.t_read = TIMING_READ;
	s->config.t_write = TIMING_WRITE;
	s->config.t_erase = TIMING_ERASE;

	/* Constants */
	s->nr_host_pages_in_blk = NR_HOST_PAGES_IN_FLASH_PAGE
						* s->nr_pages_per_blk;
	s->nr_pages = s->nr_pools * s->nr_blks_per_pool
						* s->nr_host_pages_in_blk;

	/* Invalid pages in block bitmap is preallocated. */
	if (s->nr_host_pages_in_blk >
				MAX_INVALID_PAGES_STORAGE * BITS_PER_LONG) {
		pr_err("lightnvm: Num. pages per block too high");
		return -EINVAL;
	}

	if (vsl_stor_init(dev, s) < 0) {
		pr_err("vsl: cannot initialize vsl structure");
		goto err_map;
	}

	pr_info("vsl: pls: %u blks: %u pgs: %u aps: %u ppa: %u",
		s->nr_pools,
		s->nr_blks_per_pool,
		s->nr_pages_per_blk,
		s->nr_aps,
		s->nr_aps_per_pool);
	pr_info("vsl: timings: %u/%u/%u",
			s->config.t_read,
			s->config.t_write,
			s->config.t_erase);
	pr_info("vsl: target sector size=%d", s->sector_size);
	/*pr_info("vsl: disk logical sector size=%d",
		bdev_logical_block_size(s->dev->bdev));
	pr_info("vsl: disk physical sector size=%d",
		bdev_physical_block_size(s->dev->bdev));*/
	pr_info("vsl: disk flash page size=%d", FLASH_PAGE_SIZE);
	pr_info("vsl: allocated %lu physical pages (%lu KB)",
		s->nr_pages, s->nr_pages * s->sector_size / 1024);

	dev->stor = s;
	return 0;
err_map:
	kfree(s);
	return -ENOMEM;
}

void vsl_exit(struct vsl_dev *dev)
{
	struct vsl_stor *s = dev->stor;
	struct vsl_pool *pool;
	int i;

	if (!s)
		return;

	if (s->type->exit)
		s->type->exit(s);

	del_timer(&s->gc_timer);

	/* TODO: remember outstanding block refs, waiting to be erased... */
	vsl_for_each_pool(s, pool, i)
		kfree(pool->blocks);

	kfree(s->pools);
	kfree(s->aps);

	vfree(s->trans_map);
	vfree(s->rev_trans_map);

	destroy_workqueue(s->krqd_wq);
	destroy_workqueue(s->kgc_wq);

	mempool_destroy(s->page_pool);
	mempool_destroy(s->addr_pool);

	percpu_ida_destroy(&s->free_inflight);

	kfree(s);

	kmem_cache_destroy(_addr_cache);

	pr_info("vsl: successfully unloaded");
}

int vsl_config_blk_tags(struct blk_mq_tag_set *tagset)
{
	tagset->cmd_size += sizeof(struct per_rq_data);
	tagset->ops.queue_rq = vsl_queue_rq;
}

MODULE_DESCRIPTION("OpenVSL");
MODULE_AUTHOR("Matias Bjorling <m@bjorling.me>");
MODULE_LICENSE("GPL");
