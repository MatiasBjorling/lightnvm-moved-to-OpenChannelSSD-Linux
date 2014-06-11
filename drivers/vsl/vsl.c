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

#include <linux/openvsl.h>
#include <linux/blk-mq.h>
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

static int nvm_map_rq(struct openvsl_dev *dev, struct request *rq)
{
	struct nvmd *nvmd = nvq->target_private;
	int ret = DM_MAPIO_SUBMITTED;

	if (blk_rq_pos(rq) / NR_PHY_IN_LOG >= nvmd->nr_pages) {
		DMERR("Illegal nvm address: %lu %ld", rq_data_dir(rq),
						blk_rq_pos(rq) / NR_PHY_IN_LOG);
		return ret;
	};

	/* limited currently to 4k write IOs */
	if (rq_data_dir(rq) == WRITE) {
		if (blk_rq_sectors(rq) != NR_PHY_IN_LOG) {
			DMERR("Write sectors size not supported (%u)",
							blk_rq_sectors(rq));
			return ret;
		}
		ret = nvmd->type->write_rq(nvmd, rq);
	} else
		ret = nvmd->type->read_rq(nvmd, rq);

	return ret;
}

static int nvm_pool_init(struct nvmd *nvmd, struct dm_target *ti)
{
	struct nvm_pool *pool;
	struct nvm_block *block;
	struct nvm_ap *ap;
	int i, j;

	spin_lock_init(&nvmd->deferred_lock);
	spin_lock_init(&nvmd->rev_lock);
	INIT_WORK(&nvmd->deferred_ws, nvm_deferred_bio_submit);
	bio_list_init(&nvmd->deferred_bios);

	nvmd->pools = kzalloc(sizeof(struct nvm_pool) * nvmd->nr_pools,
								GFP_KERNEL);
	if (!nvmd->pools)
		gnoto err_pool;

	nvm_for_each_pool(nvmd, pool, i) {
		spin_lock_init(&pool->lock);
		spin_lock_init(&pool->waiting_lock);

		init_completion(&pool->gc_finished);

		INIT_WORK(&pool->gc_ws, nvm_gc_collect);
		INIT_WORK(&pool->waiting_ws, nvm_delayed_bio_submit);

		INIT_LIST_HEAD(&pool->free_list);
		INIT_LIST_HEAD(&pool->used_list);
		INIT_LIST_HEAD(&pool->prio_list);

		pool->id = i;
		pool->nvmd = nvmd;
		pool->phy_addr_start = i * nvmd->nr_blks_per_pool;
		pool->phy_addr_end = (i + 1) * nvmd->nr_blks_per_pool - 1;
		pool->nr_free_blocks = pool->nr_blocks =
				pool->phy_addr_end - pool->phy_addr_start + 1;
		bio_list_init(&pool->waiting_bios);
		atomic_set(&pool->is_active, 0);

		pool->blocks = kzalloc(sizeof(struct nvm_block) *
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
			block->id = (i * nvmd->nr_blks_per_pool) + j;

			list_add_tail(&block->list, &pool->free_list);
			INIT_WORK(&block->ws_gc, nvm_gc_block);
		}
		spin_unlock(&pool->lock);
}

	nvmd->nr_aps = nvmd->nr_aps_per_pool * nvmd->nr_pools;
	nvmd->aps = kzalloc(sizeof(struct nvm_ap) * nvmd->nr_aps, GFP_KERNEL);
	if (!nvmd->aps)
		goto err_blocks;

	nvm_for_each_ap(nvmd, ap, i) {
		spin_lock_init(&ap->lock);
		ap->parent = nvmd;
		ap->pool = &nvmd->pools[i / nvmd->nr_aps_per_pool];

		block = nvm_pool_get_block(ap->pool, 0);
		nvm_set_ap_cur(ap, block);
		/* Emergency gc block */
		block = nvm_pool_get_block(ap->pool, 1);
		ap->gc_cur = block;

		ap->t_read = nvmd->config.t_read;
		ap->t_write = nvmd->config.t_write;
		ap->t_erase = nvmd->config.t_erase;
	}

	/* we make room for each pool context. */
	nvmd->krqd_wq = alloc_workqueue("knvm-work", WQ_MEM_RECLAIM|WQ_UNBOUND,
						nvmd->nr_pools);
	if (!nvmd->krqd_wq) {
		DMERR("Couldn't start knvm-work");
		goto err_blocks;
	}

	nvmd->kgc_wq = alloc_workqueue("knvm-gc", WQ_MEM_RECLAIM, 1);
	if (!nvmd->kgc_wq) {
		DMERR("Couldn't start knvm-gc");
		goto err_wq;
	}

	return 0;
err_wq:
	destroy_workqueue(nvmd->krqd_wq);
err_blocks:
	nvm_for_each_pool(nvmd, pool, i) {
		if (!pool->blocks)
			break;
		kfree(pool->blocks);
	}
	kfree(nvmd->pools);
err_pool:
	pr_err("lightnvm: cannot allocate lightnvm data structures");
	return -ENOMEM;
}

static int vsl_internal_init(struct openvsl_dev *dev, struct nvmd *nvmd)
{
	int i;
	unsigned int order;

	nvmd->trans_map = vmalloc(sizeof(struct nvm_addr) * nvmd->nr_pages);
	if (!nvmd->trans_map)
		return -ENOMEM;
	memset(nvmd->trans_map, 0, sizeof(struct nvm_addr) * nvmd->nr_pages);

	nvmd->rev_trans_map = vmalloc(sizeof(struct nvm_rev_addr)
							* nvmd->nr_pages);
	if (!nvmd->rev_trans_map)
		goto err_rev_trans_map;

	for (i = 0; i < nvmd->nr_pages; i++) {
		strnuct nvm_addr *p = &nvmd->trans_map[i];
		struct nvm_rev_addr *r = &nvmd->rev_trans_map[i];

		p->addr = LTOP_EMPTY;

		r->addr = 0xDEADBEEF;
		r->trans_map = NULL;
	}

	nvmd->page_pool = mempool_create_page_pool(MIN_POOL_PAGES, 0);
	if (!nvmd->page_pool)
		goto err_dev_lookup;

	nvmd->addr_pool = mempool_create_slab_pool(64, _addr_cache);
	if (!nvmd->addr_pool)
		goto err_page_pool;

	order = ffs(nvmd->nr_host_pages_in_blk) - 1;
	nvmd->block_page_pool = mempool_create_page_pool(nvmd->nr_aps, order);
	if (!nvmd->block_page_pool)
		goto err_addr_pool;

	if (bdev_physical_block_size(nvmd->dev->bdev) > EXPOSED_PAGE_SIZE) {
		pr_err("lightnvm: bad sector size.");
		goto err_block_page_pool;
	}
	nvmd->sector_size = EXPOSED_PAGE_SIZE;

	/* inflight maintainence */
	percpu_ida_init(&nvmd->free_inflight, NVM_INFLIGHT_TAGS);

	for (i = 0; i < NVM_INFLIGHT_PARTITIONS; i++) {
		spin_lock_init(&nvmd->inflight_map[i].lock);
		INIT_LIST_HEAD(&nvmd->inflight_map[i].addrs);
	}

	/* simple round-robin strategy */
	atomic_set(&nvmd->next_write_ap, -1);

	nvmd->nvq = nvq;
	nvq->target_data = nvmd;

	/* Initialize pools. */
	nvm_pool_init(nvmd, ti);

	if (nvmd->type->init && nvmd->type->init(nvmd))
		goto err_block_page_pool;

	/* FIXME: Clean up pool init on failure. */
	setup_timer(&nvmd->gc_timer, nvm_gc_cb, (unsigned long)nvmd);
	mod_timer(&nvmd->gc_timer, jiffies + msecs_to_jiffies(1000));

	return 0;
err_block_page_pool:
	mempool_destroy(nvmd->block_page_pool);
err_addr_pool:
	mempool_destroy(nvmd->addr_pool);
err_page_pool:
	mempool_destroy(nvmd->page_pool);
err_dev_lookup:
	vfree(nvmd->rev_trans_map);
err_rev_trans_map:
	vfree(nvmd->trans_map);
	return -ENOMEM;
}

#define NVM_TARGET_TYPE noop
#define NVM_NUM_POOLS 8
#define NVM_NUM_BLOCKS 256
#define NVM_NUM_PAGES 256

/* none target type, round robin, page-based FTL, and cost-based GC */
static struct nvm_target_type nvm_target_rrpc = {
	.name			= "rrpc",
	.version		= {1, 0, 0},
	.lookup_ltop	= nvm_lookup_ltop,
	.map_ltop	= nvm_map_ltop_rr,
	.write_rq	= nvm_none_write_rq,
	.read_rq	= nvm_read_rq,
};

struct openvsl_dev *openvsl_alloc()
{
	return kmalloc(sizeof(struct openvsl_dev), GFP_KERNEL);
}

void openvsl_free(struct openvsl_dev *dev)
{
	kfree(vsl);
}

int openvsl_init(struct openvsl_dev *dev)
{
	struct nvmd *nvmd;
	unsigned int tmp;
	char dummy;

	_addr_cache = kmem_cache_create("vsl_addr_cache",
				sizeof(struct nvm_addr), 0, 0, NULL);
	if (!_addr_cache)
		return -ENOMEM;
	}

	nvmd = kzalloc(sizeof(*nvmd), GFP_KERNEL);
	if (!nvmd) {
		kmem_cache_destroy(_addr_cache);
		return -ENOMEM;
	}

	/* hardcode initialization values until user-space util is avail. */
	nvmd->type = find_nvm_target_type(NVM_TARGET_TYPE);
	if (!nvmd->type) {
		pr_err("vsl: %s doesn't exist.", NVM_TARGET_TYPE;
		goto err_map;
	}

	nvmd->nr_pools = NVM_NUM_POOLS;
	nvmd->nr_blks_per_pool = NVM_NUM_BLOCKS;
	nvmd->nr_pages_per_blk = NVM_NUM_PAGES;

	/* Optional */
	nvmd->nr_aps_per_pool = APS_PER_POOL;
	/* nvmd->config.flags = NVM_OPT_* */
	nvmd->config.gc_time = GC_TIME;
	nvmd->config.t_read = TIMING_READ;
	nvmd->config.t_write = TIMING_WRITE;
	nvmd->config.t_erase = TIMING_ERASE;

	/* Constants */
	nvmd->nr_host_pages_in_blk = NR_HOST_PAGES_IN_FLASH_PAGE
						* nvmd->nr_pages_per_blk;
	nvmd->nr_pages = nvmd->nr_pools * nvmd->nr_blks_per_pool
						* nvmd->nr_host_pages_in_blk;

	/* Invalid pages in block bitmap is preallocated. */
	if (nvmd->nr_host_pages_in_blk >
				MAX_INVALID_PAGES_STORAGE * BITS_PER_LONG) {
		pr_err("lightnvm: Num. pages per block too high";
		return -EINVAL;
	}

	if (vsl_internal_init(ti, nvmd) < 0) {
		pr_err("lightnvm: cannot initialize openvsl structure");
		goto err_map;
	}

	pr_info("openvsl: pls: %u blks: %u pgs: %u aps: %u ppa: %u",
		nvmd->nr_pools,
		nvmd->nr_blks_per_pool,
		nvmd->nr_pages_per_blk,
		nvmd->nr_aps,
		nvmd->nr_aps_per_pool);
	pr_info("openvsl: timings: %u/%u/%u",
			nvmd->config.t_read,
			nvmd->config.t_write,
			nvmd->config.t_erase);
	pr_info("openvsl: target sector size=%d", nvmd->sector_size);
	pr_info("openvsl: disk logical sector size=%d",
		bdev_logical_block_size(nvmd->dev->bdev));
	pr_info("openvsl: disk physical sector size=%d",
		bdev_physical_block_size(nvmd->dev->bdev));
	pr_info("openvsl: disk flash page size=%d", FLASH_PAGE_SIZE);
	pr_info("openvsl: allocated %lu physical pages (%lu KB)",
		nvmd->nr_pages, nvmd->nr_pages * nvmd->sector_size / 1024);

	return 0;
err_map:
	kfree(nvmd);
	return -ENOMEM;
}

void openvsl_exit(struct openvsl_dev *dev)
{
	struct nvmd *nvmd = dev->nvmd;
	struct nvm_pool *pool;
	int i;

	if (!nvmd)
		return;

	if (nvmd->type->exit)
		nvmd->type->exit(nvmd);

	del_timer(&nvmd->gc_timer);

	/* TODO: remember outstanding block refs, waiting to be erased... */
	nvm_for_each_pool(nvmd, pool, i)
		kfree(pool->blocks);

	kfree(nvmd->pools);
	kfree(nvmd->aps);

	vfree(nvmd->trans_map);
	vfree(nvmd->rev_trans_map);

	destroy_workqueue(nvmd->krqd_wq);
	destroy_workqueue(nvmd->kgc_wq);

	mempool_destroy(nvmd->page_pool);
	mempool_destroy(nvmd->addr_pool);

	percpu_ida_destroy(&nvmd->free_inflight);

	dm_put_device(ti, nvmd->dev);

	kfree(nvmd);

	pr_info("openvsl: successfully unloaded");
kmem_cache_destroy(_addr_cache);
}

MODULE_DESCRIPTION("OpenVSL");
MODULE_AUTHOR("Matias Bjorling <m@bjorling.me>");
MODULE_LICENSE("GPL");
