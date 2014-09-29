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
#include <linux/types.h>
#include <linux/openvsl.h>
#include <linux/radix-tree.h>

#include <linux/ktime.h>
#include <trace/events/block.h>

#include "vsl.h"

/* Defaults
 * Number of append points per pool. We assume that accesses within a pool is
 * serial (NAND flash/PCM/etc.)
 */
#define APS_PER_POOL 1

/* If enabled, we delay requests on each ap to run serialized. */
#define SERIALIZE_POOL_ACCESS 0

/* Run GC every X seconds */
#define GC_TIME 10

/* Minimum pages needed within a pool */
#define MIN_POOL_PAGES 16

extern struct vsl_target_type vsl_target_rrpc;

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

static inline unsigned long time_taken(struct timespec end,
				       struct timespec start)
{
	struct timespec ts;
	ts = timespec_sub(end, start);
	BUG_ON(ts.tv_sec); /*processing time should never exceed 999us*/
	return ts.tv_nsec;
}

int vsl_queue_rq(struct vsl_dev *dev, struct request *rq)
{
	struct vsl_stor *s = dev->stor;
	int ret;

	if (rq->cmd_flags & REQ_VSL_MAPPED)
		return BLK_MQ_RQ_QUEUE_OK;

	if (blk_rq_pos(rq) / NR_PHY_IN_LOG > s->nr_pages) {
		pr_err("Illegal vsl address: %llu",
					(unsigned long long) blk_rq_pos(rq));
		return BLK_MQ_RQ_QUEUE_ERROR;
	};


	if (rq_data_dir(rq) == WRITE)
		ret = s->type->write_rq(s, rq);
	else
		ret = s->type->read_rq(s, rq);

	if (ret == BLK_MQ_RQ_QUEUE_OK)
		rq->cmd_flags |= (REQ_VSL|REQ_VSL_MAPPED);

	return ret;
}
EXPORT_SYMBOL_GPL(vsl_queue_rq);

void vsl_end_io(struct vsl_dev *vsl_dev, struct request *rq, int error)
{
	if (rq->cmd_flags & (REQ_VSL|REQ_VSL_MAPPED))
		vsl_endio(vsl_dev, rq, error);

	if (!(rq->cmd_flags & REQ_VSL))
		pr_info("Request submitted outside vsl_queue_rq detected!\n");

	blk_mq_end_io(rq, error);
}
EXPORT_SYMBOL_GPL(vsl_end_io);

void vsl_complete_request(struct vsl_dev *vsl_dev, struct request *rq)
{
	if (rq->cmd_flags & (REQ_VSL|REQ_VSL_MAPPED))
		vsl_endio(vsl_dev, rq, 0);

	if (!(rq->cmd_flags & REQ_VSL))
		pr_info("Request submitted outside vsl_queue_rq detected!\n");
	blk_mq_complete_request(rq);
}
EXPORT_SYMBOL_GPL(vsl_complete_request);

unsigned int vsl_cmd_size(void)
{
	return sizeof(struct per_rq_data);
}
EXPORT_SYMBOL_GPL(vsl_cmd_size);

static int vsl_pool_init(struct vsl_stor *s, struct vsl_dev *dev)
{
	struct vsl_pool *pool;
	struct vsl_block *block;
	struct vsl_ap *ap;
	int i, j;

	spin_lock_init(&s->rev_lock);

	s->pools = kcalloc(s->nr_pools, sizeof(struct vsl_pool), GFP_KERNEL);
	if (!s->pools)
		goto err_pool;

	vsl_for_each_pool(s, pool, i) {
		spin_lock_init(&pool->lock);
		spin_lock_init(&pool->waiting_lock);

		init_completion(&pool->gc_finished);

		INIT_WORK(&pool->gc_ws, vsl_gc_collect);

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

		pool->blocks = vzalloc(sizeof(struct vsl_block) *
							pool->nr_blocks);
		if (!pool->blocks)
			goto err_blocks;

		pool_for_each_block(pool, block, j) {
			spin_lock_init(&block->lock);
			atomic_set(&block->gc_running, 0);
			INIT_LIST_HEAD(&block->list);
			INIT_LIST_HEAD(&block->prio);

			block->pool = pool;
			block->id = (i * s->nr_blks_per_pool) + j;

			list_add_tail(&block->list, &pool->free_list);
			INIT_WORK(&block->ws_gc, vsl_gc_block);
			INIT_WORK(&block->ws_eio, vsl_gc_recycle_block);
		}
	}

	s->nr_aps = s->nr_aps_per_pool * s->nr_pools;
	s->aps = kcalloc(s->nr_aps, sizeof(struct vsl_ap), GFP_KERNEL);
	if (!s->aps)
		goto err_blocks;

	vsl_for_each_ap(s, ap, i) {
		spin_lock_init(&ap->lock);
		ap->parent = s;
		ap->pool = &s->pools[i / s->nr_aps_per_pool];

		block = s->type->pool_get_blk(ap->pool, 0);
		vsl_set_ap_cur(ap, block);

		/* Emergency gc block */
		block = s->type->pool_get_blk(ap->pool, 1);
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

	s->trans_map = vzalloc(sizeof(struct vsl_addr) * s->nr_pages);
	if (!s->trans_map)
		return -ENOMEM;

	s->rev_trans_map = vmalloc(sizeof(struct vsl_rev_addr)
							* s->nr_pages);
	if (!s->rev_trans_map)
		goto err_rev_trans_map;

	for (i = 0; i < s->nr_pages; i++) {
		struct vsl_addr *p = &s->trans_map[i];
		struct vsl_rev_addr *r = &s->rev_trans_map[i];

		p->addr = LTOP_EMPTY;
		r->addr = 0xDEADBEEF;
	}

	s->page_pool = mempool_create_page_pool(MIN_POOL_PAGES, 0);
	if (!s->page_pool)
		goto err_dev_lookup;

	s->addr_pool = mempool_create_slab_pool(64, _addr_cache);
	if (!s->addr_pool)
		goto err_page_pool;

	s->sector_size = EXPOSED_PAGE_SIZE;

	/* inflight maintenance */
	percpu_ida_init(&s->free_inflight, VSL_INFLIGHT_TAGS);

	for (i = 0; i < VSL_INFLIGHT_PARTITIONS; i++) {
		spin_lock_init(&s->inflight_map[i].lock);
		INIT_LIST_HEAD(&s->inflight_map[i].reqs);
	}

	/* simple round-robin strategy */
	atomic_set(&s->next_write_ap, -1);

	s->dev = (void *)dev;
	dev->stor = s;

	/* Initialize pools. */
	vsl_pool_init(s, dev);

	if (s->type->init && s->type->init(s))
		goto err_addr_pool;

	/* FIXME: Clean up pool init on failure. */
	setup_timer(&s->gc_timer, vsl_gc_cb, (unsigned long)s);
	mod_timer(&s->gc_timer, jiffies + msecs_to_jiffies(1000));

	return 0;
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

struct vsl_dev *vsl_alloc()
{
	return kmalloc(sizeof(struct vsl_dev), GFP_KERNEL);
}
EXPORT_SYMBOL_GPL(vsl_alloc);

void vsl_free(struct vsl_dev *dev)
{
	kfree(dev);
}
EXPORT_SYMBOL_GPL(vsl_free);

int vsl_queue_init(struct vsl_dev *dev)
{
	int nr_sectors_per_page = 8; /* 512 bytes */

	if (queue_logical_block_size(dev->q) > (nr_sectors_per_page << 9)) {
		pr_err("vsl: logical page size not supported by hardware");
		return false;
	}

	return true;
}

int vsl_init(struct gendisk *disk, struct vsl_dev *dev)
{
	struct vsl_stor *s;
	struct vsl_id vsl_id;
	struct vsl_id_chnl vsl_id_chnl;

	unsigned long size;

	if (!dev->ops->identify)
		return -EINVAL;

	if (!vsl_queue_init(dev))
		return -EINVAL;

	_addr_cache = kmem_cache_create("vsl_addr_cache",
				sizeof(struct vsl_addr), 0, 0, NULL);
	if (!_addr_cache)
		return -ENOMEM;

	vsl_register_target(&vsl_target_rrpc);

	s = kzalloc(sizeof(struct vsl_stor), GFP_KERNEL);
	if (!s) {
		goto err;
	}

	/* hardcode initialization values until user-space util is avail. */
	s->type = &vsl_target_rrpc;
	if (!s->type) {
		pr_err("vsl: %s doesn't exist.", VSL_TARGET_TYPE);
		goto err_target;
	}

	if (dev->ops->identify(dev, &vsl_id))
		goto err_target;

	s->nr_pools = vsl_id.nchannels;

	/* TODO: We're limited to the same setup for each channel */
	if (dev->ops->identify_channel(dev, 0, &vsl_id_chnl))
		goto err_target;

	size = vsl_id_chnl.laddr_end - vsl_id_chnl.laddr_begin + 1;

	s->gran_blk = vsl_id_chnl.gran_erase;
	s->gran_read = vsl_id_chnl.gran_read;
	s->gran_write = vsl_id_chnl.gran_write;

	s->nr_blks_per_pool = size / s->gran_blk / vsl_id.nchannels;
	/*FIXME: gran_{read,write} may differ */
	s->nr_pages_per_blk = s->gran_blk / s->gran_read * (s->gran_read / EXPOSED_PAGE_SIZE);

	s->nr_aps_per_pool = APS_PER_POOL;
	/* s->config.flags = VSL_OPT_* */
	s->config.gc_time = GC_TIME;
	s->config.t_read = vsl_id_chnl.t_r / 1000;
	s->config.t_write = vsl_id_chnl.t_w / 1000;
	s->config.t_erase = vsl_id_chnl.t_e / 1000;

	/* Constants */
	s->nr_pages = s->nr_pools * s->nr_blks_per_pool * s->nr_pages_per_blk;

	if (vslkv_init(s, size)) {
		printk("vslkv_init failed\n");
		goto err_target;
	}

	if (s->nr_pages_per_blk >
				MAX_INVALID_PAGES_STORAGE * BITS_PER_LONG) {
		pr_err("lightnvm: Num. pages per block too high. Increase MAX_INVALID_PAGES_STORAGE.");
		return -EINVAL;
	}

	if (vsl_stor_init(dev, s) < 0) {
		pr_err("vsl: cannot initialize vsl structure");
		goto err_map;
	}

	pr_info("vsl: pls: %u blks: %u pgs: %u aps: %u ppa: %u\n",
		s->nr_pools,
		s->nr_blks_per_pool,
		s->nr_pages_per_blk,
		s->nr_aps,
		s->nr_aps_per_pool);
	pr_info("vsl: timings: %u/%u/%u\n",
			s->config.t_read,
			s->config.t_write,
			s->config.t_erase);
	pr_info("vsl: target sector size=%d\n", s->sector_size);
	pr_info("vsl: disk flash size=%d map size=%d\n", s->gran_read, EXPOSED_PAGE_SIZE);
	pr_info("vsl: allocated %lu physical pages (%lu KB)\n",
		s->nr_pages, s->nr_pages * s->sector_size / 1024);

	dev->stor = s;
	return 0;

err_map:
	vslkv_exit(s);
err_target:
	kfree(s);
err:
	kmem_cache_destroy(_addr_cache);
	pr_err("Failed to initialize vsl\n");
	return -ENOMEM;
}
EXPORT_SYMBOL_GPL(vsl_init);

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

int vsl_ioctl(struct vsl_dev *dev, fmode_t mode, unsigned int cmd,
							unsigned long arg)
{
	switch(cmd) {
	case OPENVSL_IOCTL_KV:
		return vslkv_unpack(dev, (void __user *)arg);
	default:
		return -ENOTTY;
	}
}
EXPORT_SYMBOL_GPL(vsl_ioctl);

#ifdef CONFIG_COMPAT
int vsl_compat_ioctl(struct vsl_dev *dev, fmode_t mode,
		unsigned int cmd, unsigned long arg)
{
	return vsl_ioctl(dev, mode, cmd, arg);
}
EXPORT_SYMBOL_GPL(vsl_compat_ioctl);
#else
#define vsl_compat_ioctl	NULL
#endif

MODULE_DESCRIPTION("OpenVSL");
MODULE_AUTHOR("Matias Bjorling <m@bjorling.me>");
MODULE_LICENSE("GPL");
