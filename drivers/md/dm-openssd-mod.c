/*
 * Copyright (C) 2012 Matias Bjørling.
 *
 * This file is released under GPL.
 *
 * Todo
 *
 * - Implement fetching of bad pages from flash
 *
 * Hints
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

#include "dm-openssd.h"
#include "dm-openssd-hint.h"

/* Defaults */

/* Number of append points per pool. We assume that accesses within a pool is
 * serial (NAND flash/PCM/etc.) */
#define APS_PER_POOL 1

/* If enabled, we delay bios on each ap to run serialized. */
#define SERIALIZE_POOL_ACCESS 0

/* Sleep timings before simulating device specific storage (in us)*/
#define TIMING_READ 25
#define TIMING_WRITE 500
#define TIMING_ERASE 1500

/* Run GC every X seconds */
#define GC_TIME 10

static struct kmem_cache *_per_bio_cache;

static int openssd_kthread(void *data)
{
	struct openssd *os = (struct openssd *)data;
	BUG_ON(!os);

	while (!kthread_should_stop()) {

		openssd_gc_collect(os);

		schedule_timeout_uninterruptible(os->config.gc_time * HZ);
	}

	return 0;
}

static int openssd_ioctl(struct dm_target *ti, unsigned int cmd,
                         unsigned long arg)
{
	struct openssd *os;
	struct dm_dev *dev;

	os = (struct openssd *) ti->private;
	dev = os->dev;

	DMDEBUG("got ioctl %x\n", cmd);

	switch (cmd) {
	case OPENSSD_IOCTL_ID:
		return 12345678; // TODO: anything else?
		break;
	}

	return openssd_ioctl_hint(os, cmd, arg);
}

static int openssd_map(struct dm_target *ti, struct bio *bio)
{
	struct openssd *os = ti->private;
	int ret;
	bio->bi_bdev = os->dev->bdev;

	if (bio_data_dir(bio) == WRITE)
		ret = os->write_bio(os, bio);
	else
		ret = os->read_bio(os, bio);

	DMDEBUG("openssd_map: %s l_addr %ld, map done", (bio_data_dir(bio) ==
	                WRITE) ? "WRITE" : "READ", bio->bi_sector/8);

	return ret;
}

static void openssd_status(struct dm_target *ti, status_type_t type,
                           unsigned status_flags, char *result, unsigned maxlen)
{
	struct openssd *os = ti->private;
	struct nvm_ap *ap;
	int i, sz = 0;

	switch(type) {
	case STATUSTYPE_INFO:
		DMEMIT("Use table information");
		break;
	case STATUSTYPE_TABLE:
		ssd_for_each_ap(os, ap, i) {
			DMEMIT("Reads: %lu Writes: %lu Delayed: %lu",
			       ap->io_accesses[0], ap->io_accesses[1],
			       ap->io_delayed);
		}
		break;
	}
}

static int nvm_pool_init(struct openssd *os, struct dm_target *ti)
{
	struct nvm_pool *pool;
	struct nvm_block *block;
	struct nvm_ap *ap;
	int i, j;

	spin_lock_init(&os->gc_lock);

	os->pools = kzalloc(sizeof(struct nvm_pool) * os->nr_pools, GFP_KERNEL);
	if (!os->pools)
		goto err_pool;

	ssd_for_each_pool(os, pool, i) {
		spin_lock_init(&pool->lock);

		INIT_LIST_HEAD(&pool->free_list);
		INIT_LIST_HEAD(&pool->used_list);
		INIT_LIST_HEAD(&pool->prio_list);

		pool->phy_addr_start = i * os->nr_blks_per_pool;
		pool->phy_addr_end = (i + 1) * os->nr_blks_per_pool - 1;

		pool->nr_free_blocks = pool->nr_blocks = pool->phy_addr_end - pool->phy_addr_start + 1;
		pool->blocks = kzalloc(sizeof(struct nvm_block) * pool->nr_blocks, GFP_KERNEL);
		pool->os = os;
		spin_lock_init(&pool->waiting_lock);
		bio_list_init(&pool->waiting_bios);
		INIT_WORK(&pool->waiting_ws, openssd_delayed_bio_submit);
		atomic_set(&pool->is_active, 0);

		if (!pool->blocks)
			goto err_blocks;

		pool_for_each_block(pool, block, j) {
			spin_lock_init(&block->lock);
			spin_lock_init(&block->gc_lock);

			if (percpu_ref_init(&block->ref_count, openssd_block_release))
				goto err_blocks;

			block->pool = pool;
			block->id = (i * os->nr_blks_per_pool) + j;

			openssd_reset_block(block);

			list_add_tail(&block->list, &pool->free_list);
			list_add_tail(&block->prio, &pool->prio_list);
		}
	}

	os->nr_aps = os->nr_aps_per_pool * os->nr_pools;
	os->aps = kmalloc(sizeof(struct nvm_ap) * os->nr_pools * os->nr_aps, GFP_KERNEL);
	if (!os->aps)
		goto err_blocks;

	ssd_for_each_pool(os, pool, i) {
		for (j = 0; j < os->nr_aps_per_pool; j++) {
			ap = &os->aps[(i * os->nr_aps_per_pool) + j];

			spin_lock_init(&ap->lock);
			ap->parent = os;
			ap->pool = pool;
			ap->cur = nvm_pool_get_block(pool); // No need to lock ap->cur.

			ap->t_read = os->config.t_read;
			ap->t_write = os->config.t_write;
			ap->t_erase = os->config.t_erase;
		}
	}

	os->kbiod_wq = alloc_workqueue("kopenssd-work", WQ_MEM_RECLAIM, 0);
	if (!os->kbiod_wq) {
		DMERR("Couldn't start kopenssd-worker");
		goto err_blocks;
	}

	return 0;
err_blocks:
	ssd_for_each_pool(os, pool, i) {
		if (!pool->blocks)
			break;
		pool_for_each_block(pool, block, j) {
			percpu_ref_cancel_init(&block->ref_count);
		}
		kfree(pool->blocks);
	}
	kfree(os->pools);
err_pool:
	ti->error = "dm-openssd: Cannot allocate openssd data structures";
	return -ENOMEM;
}

static int nvm_init(struct dm_target *ti, struct openssd *os)
{
	int i;

	os->nr_host_pages_in_blk = NR_HOST_PAGES_IN_FLASH_PAGE * os->nr_pages_per_blk;
	os->nr_pages = os->nr_pools * os->nr_blks_per_pool * os->nr_host_pages_in_blk;

	/* Invalid pages in block bitmap is preallocated. */
	if (os->nr_host_pages_in_blk > MAX_INVALID_PAGES_STORAGE * BITS_PER_LONG)
		return -EINVAL;

	os->trans_map = vmalloc(sizeof(struct nvm_addr) * os->nr_pages);
	if (!os->trans_map)
		return -ENOMEM;
	memset(os->trans_map, 0, sizeof(struct nvm_addr) * os->nr_pages);

	// initial l2p is LTOP_EMPTY
	for (i = 0; i < os->nr_pages; i++)
		os->trans_map[i].addr = LTOP_EMPTY;

	os->rev_trans_map = vmalloc(sizeof(sector_t) * os->nr_pages);
	if (!os->rev_trans_map)
		goto err_rev_trans_map;

	os->per_bio_pool = mempool_create_slab_pool(16, _per_bio_cache);
	if (!os->per_bio_pool)
		goto err_dev_lookup;

	if (bdev_physical_block_size(os->dev->bdev) > EXPOSED_PAGE_SIZE) {
		ti->error = "dm-openssd: Got bad sector size. Device sector size \
			is larger than exposed";
		goto err_per_bio_pool;
	}
	os->sector_size = EXPOSED_PAGE_SIZE;

	// Simple round-robin strategy
	atomic_set(&os->next_write_ap, -1);

	os->lookup_ltop = openssd_lookup_ltop;
	os->lookup_ptol = openssd_lookup_ptol;
	os->map_ltop = openssd_alloc_map_ltop_rr;
	os->write_bio = openssd_write_bio_generic;
	os->read_bio = openssd_read_bio_generic;

	os->ti = ti;
	ti->private = os;

	/* Initialize pools. */
	nvm_pool_init(os, ti);

	if (openssd_alloc_hint(os))
		goto err_per_bio_pool;

	// FIXME: Clean up pool init on failure.
	os->kt_openssd = kthread_run(openssd_kthread, os, "kopenssd");
	if (!os->kt_openssd)
		goto err_per_bio_pool;

	return 0;
err_per_bio_pool:
	mempool_destroy(os->per_bio_pool);
err_dev_lookup:
	vfree(os->rev_trans_map);
err_rev_trans_map:
	vfree(os->trans_map);
	return -ENOMEM;
}

/*
 * Accepts an OpenSSD-backed block-device. The OpenSSD device should run the
 * corresponding physical firmware that exports the flash as physical without any
 * mapping and garbage collection as it will be taken care of.
 */
static int openssd_ctr(struct dm_target *ti, unsigned argc, char **argv)
{
	struct openssd *os;
	unsigned int tmp;
	char dummy;

	// Which device it should map onto?
	if (argc < 5) {
		ti->error = "Insufficient arguments";
		return -EINVAL;
	}

	os = kzalloc(sizeof(*os), GFP_KERNEL);
	if (!os) {
		ti->error = "Cannot allocate data structures";
		return -ENOMEM;
	}

	if (dm_get_device(ti, argv[0], dm_table_get_mode(ti->table), &os->dev))
		goto err_map;

	if (!strcmp(argv[1], "swap"))
		os->config.flags |= NVM_OPT_ENGINE_SWAP;
	else if (!strcmp(argv[1], "hint"))
		os->config.flags |=
		        (NVM_OPT_ENGINE_LATENCY | NVM_OPT_ENGINE_IOCTL);

	if (sscanf(argv[2], "%u%c", &tmp, &dummy) != 1) {
		ti->error = "Cannot read number of pools";
		goto err_map;
	}
	os->nr_pools = tmp;

	if (sscanf(argv[3], "%u%c", &tmp, &dummy) != 1) {
		ti->error = "Cannot read number of blocks within a pool";
		goto err_map;
	}
	os->nr_blks_per_pool = tmp;

	if (sscanf(argv[4], "%u%c", &tmp, &dummy) != 1) {
		ti->error = "Cannot read number of pages within a block";
		goto err_map;
	}
	os->nr_pages_per_blk = tmp;

	/* Optional */
	os->nr_aps_per_pool = APS_PER_POOL;
	if (argc > 5) {
		if (sscanf(argv[5], "%u%c", &tmp, &dummy) == 1) {
			os->nr_aps_per_pool = tmp;
		} else {
			ti->error = "Cannot read number of append points";
			goto err_map;
		}
	}

	if (argc > 6) {
		if (sscanf(argv[6], "%u%c", &tmp, &dummy) == 1) {
			os->config.flags = tmp;
		} else {
			ti->error = "Cannot read flags";
			goto err_map;
		}
	}

	os->config.gc_time = GC_TIME;
	if (argc > 7) {
		if (sscanf(argv[7], "%u%c", &tmp, &dummy) == 1) {
			os->config.gc_time = tmp;
		} else {
			ti->error = "Cannot read gc timing";
			goto err_map;
		}
	}

	os->config.t_read = TIMING_READ;
	if (argc > 8) {
		if (sscanf(argv[8], "%u%c", &tmp, &dummy) == 1) {
			os->config.t_read = tmp;
		} else {
			ti->error = "Cannot read read access timing";
			goto err_map;
		}
	}

	os->config.t_write = TIMING_WRITE;
	if (argc > 9) {
		if (sscanf(argv[9], "%u%c", &tmp, &dummy) == 1) {
			os->config.t_write = tmp;
		} else {
			ti->error = "Cannot read write access timing";
			goto err_map;
		}
	}

	os->config.t_erase = TIMING_ERASE;
	if (argc > 10) {
		if (sscanf(argv[10], "%u%c", &tmp, &dummy) == 1) {
			os->config.t_erase = tmp;
		} else {
			ti->error = "Cannot read erase access timing";
			goto err_map;
		}
	}

	if (nvm_init(ti, os) < 0) {
		ti->error = "Cannot initialize openssd structure";
		goto err_map;
	}

	DMINFO("Configured with");
	DMINFO("Pools: %u Blocks: %u Pages: %u Host Pages: %u \
			Aps: %u Aps Pool: %u",
	       os->nr_pools,
	       os->nr_blks_per_pool,
	       os->nr_pages_per_blk,
	       os->nr_host_pages_in_blk,
	       os->nr_aps,
	       os->nr_aps_per_pool);
	DMINFO("Target sector size=%d", os->sector_size);
	DMINFO("Disk logical sector size=%d",
	       bdev_logical_block_size(os->dev->bdev));
	DMINFO("Disk physical sector size=%d",
	       bdev_physical_block_size(os->dev->bdev));
	DMINFO("Disk flash page size=%d", FLASH_PAGE_SIZE);
	DMINFO("Allocated %lu physical pages (%lu KB)",
	       os->nr_pages, os->nr_pages * os->sector_size / 1024);

	return 0;
err_map:
	kfree(os);
	return -ENOMEM;
}

static void openssd_dtr(struct dm_target *ti)
{
	struct openssd *os = (struct openssd *) ti->private;
	struct nvm_pool *pool;
	int i;

	dm_put_device(ti, os->dev);

	ssd_for_each_pool(os, pool, i) {
		while (bio_list_peek(&pool->waiting_bios))
			flush_scheduled_work();
	}

	kthread_stop(os->kt_openssd);

	/* TODO: remember outstanding block refs, waiting to be erased... */
	ssd_for_each_pool(os, pool, i)
	kfree(pool->blocks);

	kfree(os->pools);
	kfree(os->aps);

	vfree(os->trans_map);
	vfree(os->rev_trans_map);

	destroy_workqueue(os->kbiod_wq);
	mempool_destroy(os->per_bio_pool);

	openssd_free_hint(os);

	kfree(os);

	DMINFO("dm-openssd successfully unloaded");
}

static struct target_type openssd_target = {
	.name		= "openssd",
	.version	= {1, 0, 0},
	.module		= THIS_MODULE,
	.ctr		= openssd_ctr,
	.dtr		= openssd_dtr,
	.map		= openssd_map,
	.ioctl		= openssd_ioctl,
	.status		= openssd_status,
};

static int __init dm_openssd_init(void)
{
	int ret = -ENOMEM;

	_per_bio_cache = kmem_cache_create("openssd_per_bio_cache",
	                                   sizeof(struct per_bio_data), 0, 0, NULL);
	if (!_per_bio_cache)
		return ret;

	ret = dm_register_target(&openssd_target);
	if (ret < 0)
		DMERR("register failed %d", ret);

	return ret;
}

static void __exit dm_openssd_exit(void)
{
	kmem_cache_destroy(_per_bio_cache);
	dm_unregister_target(&openssd_target);
}

module_init(dm_openssd_init);
module_exit(dm_openssd_exit);

MODULE_DESCRIPTION(DM_NAME " target");
MODULE_AUTHOR("Matias Bjorling <m@bjorling.me>");
MODULE_LICENSE("GPL");
