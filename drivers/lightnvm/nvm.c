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
 * - Implement per-cpu nvm_block data structure ownership. Removes need
 *   for taking lock on block next_write_id function. I.e. page allocation
 *   becomes nearly lockless, with occasionally movement of blocks on
 *   nvm_block lists.
 */

#include <linux/blk-mq.h>
#include <linux/list.h>
#include <linux/sem.h>
#include <linux/types.h>
#include <linux/lightnvm.h>

#include <linux/ktime.h>
#include <trace/events/block.h>

#include "nvm.h"

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

extern struct nvm_target_type nvm_target_rrpc;

static struct kmem_cache *_addr_cache;

static LIST_HEAD(_targets);
static DECLARE_RWSEM(_lock);

inline struct nvm_target_type *find_nvm_target_type(const char *name)
{
	struct nvm_target_type *t;

	list_for_each_entry(t, &_targets, list)
		if (!strcmp(name, t->name))
			return t;

	return NULL;
}

int nvm_register_target(struct nvm_target_type *t)
{
	int ret = 0;

	down_write(&_lock);
	if (find_nvm_target_type(t->name))
		ret = -EEXIST;
	else
		list_add(&t->list, &_targets);
	up_write(&_lock);
	return ret;
}

void nvm_unregister_target(struct nvm_target_type *t)
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

int nvm_queue_rq(struct nvm_dev *dev, struct request *rq)
{
	struct nvm_stor *s = dev->stor;
	int ret;

	if (rq->cmd_flags & REQ_NVM_MAPPED)
		return BLK_MQ_RQ_QUEUE_OK;

	if (blk_rq_pos(rq) / NR_PHY_IN_LOG > s->nr_pages) {
		pr_err("Illegal nvm address: %llu",
					(unsigned long long) blk_rq_pos(rq));
		return BLK_MQ_RQ_QUEUE_ERROR;
	};


	if (rq_data_dir(rq) == WRITE)
		ret = s->type->write_rq(s, rq);
	else
		ret = s->type->read_rq(s, rq);

	if (ret == BLK_MQ_RQ_QUEUE_OK)
		rq->cmd_flags |= (REQ_NVM|REQ_NVM_MAPPED);

	return ret;
}
EXPORT_SYMBOL_GPL(nvm_queue_rq);

void nvm_end_io(struct nvm_dev *nvm_dev, struct request *rq, int error)
{
	if (rq->cmd_flags & (REQ_NVM|REQ_NVM_MAPPED))
		nvm_endio(nvm_dev, rq, error);

	if (!(rq->cmd_flags & REQ_NVM))
		pr_info("Request submitted outside nvm_queue_rq detected!\n");

	blk_mq_end_io(rq, error);
}
EXPORT_SYMBOL_GPL(nvm_end_io);

void nvm_complete_request(struct nvm_dev *nvm_dev, struct request *rq)
{
	if (rq->cmd_flags & (REQ_NVM|REQ_NVM_MAPPED))
		nvm_endio(nvm_dev, rq, 0);

	if (!(rq->cmd_flags & REQ_NVM))
		pr_info("Request submitted outside nvm_queue_rq detected!\n");
	blk_mq_complete_request(rq);
}
EXPORT_SYMBOL_GPL(nvm_complete_request);

unsigned int nvm_cmd_size(void)
{
	return sizeof(struct per_rq_data);
}
EXPORT_SYMBOL_GPL(nvm_cmd_size);

static int nvm_pool_init(struct nvm_stor *s, struct nvm_dev *dev)
{
	struct nvm_pool *pool;
	struct nvm_block *block;
	struct nvm_ap *ap;
	int i, j;

	spin_lock_init(&s->rev_lock);

	s->pools = kcalloc(s->nr_pools, sizeof(struct nvm_pool), GFP_KERNEL);
	if (!s->pools)
		goto err_pool;

	nvm_for_each_pool(s, pool, i) {
		spin_lock_init(&pool->lock);
		spin_lock_init(&pool->waiting_lock);

		init_completion(&pool->gc_finished);

		INIT_WORK(&pool->gc_ws, nvm_gc_collect);

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

		pool->blocks = vzalloc(sizeof(struct nvm_block) *
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
			INIT_WORK(&block->ws_gc, nvm_gc_block);
			INIT_WORK(&block->ws_eio, nvm_gc_recycle_block);
		}
	}

	s->nr_aps = s->nr_aps_per_pool * s->nr_pools;
	s->aps = kcalloc(s->nr_aps, sizeof(struct nvm_ap), GFP_KERNEL);
	if (!s->aps)
		goto err_blocks;

	nvm_for_each_ap(s, ap, i) {
		spin_lock_init(&ap->lock);
		ap->parent = s;
		ap->pool = &s->pools[i / s->nr_aps_per_pool];

		block = s->type->pool_get_blk(ap->pool, 0);
		nvm_set_ap_cur(ap, block);

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
	nvm_for_each_pool(s, pool, i) {
		if (!pool->blocks)
			break;
		kfree(pool->blocks);
	}
	kfree(s->pools);
err_pool:
	pr_err("lightnvm: cannot allocate lightnvm data structures");
	return -ENOMEM;
}

static int nvm_stor_init(struct nvm_dev *dev, struct nvm_stor *s)
{
	int i;

	s->trans_map = vzalloc(sizeof(struct nvm_addr) * s->nr_pages);
	if (!s->trans_map)
		return -ENOMEM;

	s->rev_trans_map = vmalloc(sizeof(struct nvm_rev_addr)
							* s->nr_pages);
	if (!s->rev_trans_map)
		goto err_rev_trans_map;

	for (i = 0; i < s->nr_pages; i++) {
		struct nvm_addr *p = &s->trans_map[i];
		struct nvm_rev_addr *r = &s->rev_trans_map[i];

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
	percpu_ida_init(&s->free_inflight, NVM_INFLIGHT_TAGS);

	for (i = 0; i < NVM_INFLIGHT_PARTITIONS; i++) {
		spin_lock_init(&s->inflight_map[i].lock);
		INIT_LIST_HEAD(&s->inflight_map[i].reqs);
	}

	/* simple round-robin strategy */
	atomic_set(&s->next_write_ap, -1);

	s->dev = (void *)dev;
	dev->stor = s;

	/* Initialize pools. */
	nvm_pool_init(s, dev);

	if (s->type->init && s->type->init(s))
		goto err_addr_pool;

	/* FIXME: Clean up pool init on failure. */
	setup_timer(&s->gc_timer, nvm_gc_cb, (unsigned long)s);
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

#define NVM_TARGET_TYPE "rrpc"
#define NVM_NUM_POOLS 8
#define NVM_NUM_BLOCKS 256
#define NVM_NUM_PAGES 256

struct nvm_dev *nvm_alloc()
{
	return kmalloc(sizeof(struct nvm_dev), GFP_KERNEL);
}
EXPORT_SYMBOL_GPL(nvm_alloc);

void nvm_free(struct nvm_dev *dev)
{
	kfree(dev);
}
EXPORT_SYMBOL_GPL(nvm_free);

int nvm_queue_init(struct nvm_dev *dev)
{
	int nr_sectors_per_page = 8; /* 512 bytes */

	if (queue_logical_block_size(dev->q) > (nr_sectors_per_page << 9)) {
		pr_err("nvm: logical page size not supported by hardware");
		return false;
	}

	return true;
}

int nvm_init(struct gendisk *disk, struct nvm_dev *dev)
{
	struct nvm_stor *s;
	struct nvm_id nvm_id;
	struct nvm_id_chnl nvm_id_chnl;

	unsigned long size;

	if (!dev->ops->identify)
		return -EINVAL;

	if (!nvm_queue_init(dev))
		return -EINVAL;

	_addr_cache = kmem_cache_create("nvm_addr_cache",
				sizeof(struct nvm_addr), 0, 0, NULL);
	if (!_addr_cache)
		return -ENOMEM;

	nvm_register_target(&nvm_target_rrpc);

	s = kzalloc(sizeof(struct nvm_stor), GFP_KERNEL);
	if (!s) {
		goto err;
	}

	/* hardcode initialization values until user-space util is avail. */
	s->type = &nvm_target_rrpc;
	if (!s->type) {
		pr_err("nvm: %s doesn't exist.", NVM_TARGET_TYPE);
		goto err_target;
	}

	if (dev->ops->identify(dev, &nvm_id))
		goto err_target;

	s->nr_pools = nvm_id.nchannels;

	/* TODO: We're limited to the same setup for each channel */
	if (dev->ops->identify_channel(dev, 0, &nvm_id_chnl))
		goto err_target;

	size = nvm_id_chnl.laddr_end - nvm_id_chnl.laddr_begin + 1;

	s->gran_blk = nvm_id_chnl.gran_erase;
	s->gran_read = nvm_id_chnl.gran_read;
	s->gran_write = nvm_id_chnl.gran_write;

	s->nr_blks_per_pool = size / s->gran_blk / nvm_id.nchannels;
	/*FIXME: gran_{read,write} may differ */
	s->nr_pages_per_blk = s->gran_blk / s->gran_read * (s->gran_read / EXPOSED_PAGE_SIZE);

	s->nr_aps_per_pool = APS_PER_POOL;
	/* s->config.flags = NVM_OPT_* */
	s->config.gc_time = GC_TIME;
	s->config.t_read = nvm_id_chnl.t_r / 1000;
	s->config.t_write = nvm_id_chnl.t_w / 1000;
	s->config.t_erase = nvm_id_chnl.t_e / 1000;

	/* Constants */
	s->nr_pages = s->nr_pools * s->nr_blks_per_pool * s->nr_pages_per_blk;

	if (nvmkv_init(s, size)) {
		printk("nvmkv_init failed\n");
		goto err_target;
	}

	if (s->nr_pages_per_blk >
				MAX_INVALID_PAGES_STORAGE * BITS_PER_LONG) {
		pr_err("lightnvm: Num. pages per block too high. Increase MAX_INVALID_PAGES_STORAGE.");
		return -EINVAL;
	}

	if (nvm_stor_init(dev, s) < 0) {
		pr_err("nvm: cannot initialize nvm structure");
		goto err_map;
	}

	pr_info("nvm: pls: %u blks: %u pgs: %u aps: %u ppa: %u\n",
		s->nr_pools,
		s->nr_blks_per_pool,
		s->nr_pages_per_blk,
		s->nr_aps,
		s->nr_aps_per_pool);
	pr_info("nvm: timings: %u/%u/%u\n",
			s->config.t_read,
			s->config.t_write,
			s->config.t_erase);
	pr_info("nvm: target sector size=%d\n", s->sector_size);
	pr_info("nvm: disk flash size=%d map size=%d\n", s->gran_read, EXPOSED_PAGE_SIZE);
	pr_info("nvm: allocated %lu physical pages (%lu KB)\n",
		s->nr_pages, s->nr_pages * s->sector_size / 1024);

	dev->stor = s;
	return 0;

err_map:
	nvmkv_exit(s);
err_target:
	kfree(s);
err:
	kmem_cache_destroy(_addr_cache);
	pr_err("Failed to initialize nvm\n");
	return -ENOMEM;
}
EXPORT_SYMBOL_GPL(nvm_init);

void nvm_exit(struct nvm_dev *dev)
{
	struct nvm_stor *s = dev->stor;
	struct nvm_pool *pool;
	int i;

	if (!s)
		return;

	if (s->type->exit)
		s->type->exit(s);

	del_timer(&s->gc_timer);

	/* TODO: remember outstanding block refs, waiting to be erased... */
	nvm_for_each_pool(s, pool, i)
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

	pr_info("nvm: successfully unloaded");
}

int nvm_ioctl(struct nvm_dev *dev, fmode_t mode, unsigned int cmd,
							unsigned long arg)
{
	switch(cmd) {
	case LIGHTNVM_IOCTL_KV:
		return nvmkv_unpack(dev, (void __user *)arg);
	default:
		return -ENOTTY;
	}
}
EXPORT_SYMBOL_GPL(nvm_ioctl);

#ifdef CONFIG_COMPAT
int nvm_compat_ioctl(struct nvm_dev *dev, fmode_t mode,
		unsigned int cmd, unsigned long arg)
{
	return nvm_ioctl(dev, mode, cmd, arg);
}
EXPORT_SYMBOL_GPL(nvm_compat_ioctl);
#else
#define nvm_compat_ioctl	NULL
#endif

MODULE_DESCRIPTION("LightNVM");
MODULE_AUTHOR("Matias Bjorling <mabj@itu.dk>");
MODULE_LICENSE("GPL");
