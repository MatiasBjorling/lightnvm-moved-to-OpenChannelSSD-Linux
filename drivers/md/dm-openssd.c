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
 * - Implement per-cpu openssd_pool_block data structure ownership. Removes need
 *   for taking lock on block next_write_id function. I.e. page allocation
 *   becomes nearly lockless, with occasionally movement of blocks on
 *   openssd_pool_block lists.
 */

#include "dm-openssd.h"
#include "dm-openssd-hint.h"

static int openssd_kthread(void *data)
{
	struct openssd *os = (struct openssd *)data;
	BUG_ON(!os);

	while (!kthread_should_stop()) {

		openssd_gc_collect(os);

		schedule_timeout_uninterruptible(GC_TIME * HZ);
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
	struct openssd_ap *ap;
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

static int openssd_pool_init(struct openssd *os, struct dm_target *ti)
{
	struct openssd_pool *pool;
	struct openssd_pool_block *block;
	struct openssd_ap *ap;
	int i, j;

	spin_lock_init(&os->gc_lock);

	os->nr_pools = POOL_COUNT;
	os->pools = kzalloc(sizeof(struct openssd_pool) * os->nr_pools, GFP_KERNEL);
	if (!os->pools)
		goto err_pool;

	ssd_for_each_pool(os, pool, i) {
		spin_lock_init(&pool->lock);

		INIT_LIST_HEAD(&pool->free_list);
		INIT_LIST_HEAD(&pool->used_list);
		INIT_LIST_HEAD(&pool->prio_list);

		pool->phy_addr_start = i * POOL_BLOCK_COUNT;
		pool->phy_addr_end = (i + 1) * POOL_BLOCK_COUNT - 1;

		pool->nr_free_blocks = pool->nr_blocks = pool->phy_addr_end - pool->phy_addr_start + 1;
		pool->blocks = kzalloc(sizeof(struct openssd_pool_block) * pool->nr_blocks, GFP_KERNEL);
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

			block->parent = pool;
			block->id = (i * POOL_BLOCK_COUNT) + j;

			openssd_reset_block(block);

			list_add_tail(&block->list, &pool->free_list);
			list_add_tail(&block->prio, &pool->prio_list);
		}
	}

	os->nr_aps = os->nr_aps_per_pool * os->nr_pools;
	os->aps = kmalloc(sizeof(struct openssd_ap) * os->nr_pools * os->nr_aps, GFP_KERNEL);
	if (!os->aps)
		goto err_blocks;

	ssd_for_each_pool(os, pool, i) {
		for (j = 0; j < os->nr_aps_per_pool; j++) {
			ap = &os->aps[(i * os->nr_aps_per_pool) + j];

			spin_lock_init(&ap->lock);
			ap->parent = os;
			ap->pool = pool;
			ap->cur = openssd_pool_get_block(pool); // No need to lock ap->cur.

			ap->t_read = TIMING_READ;
			ap->t_write = TIMING_WRITE;
			ap->t_erase = TIMING_ERASE;
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

/*
 * Accepts an OpenSSD-backed block-device. The OpenSSD device should run the
 * corresponding physical firmware that exports the flash as physical without any
 * mapping and garbage collection as it will be taken care of.
 */
static int openssd_ctr(struct dm_target *ti, unsigned argc, char **argv)
{
	struct openssd *os;
	int i;

	// Which device it should map onto?
	if (argc != 1) {
		ti->error = "The target takes a single block device path as argument.";
		return -EINVAL;
	}

	os = kzalloc(sizeof(*os), GFP_KERNEL);
	if (os == NULL)
		return -ENOMEM;

	os->nr_pages = POOL_COUNT * POOL_BLOCK_COUNT * NR_HOST_PAGES_IN_BLOCK;

	os->trans_map = vmalloc(sizeof(struct openssd_addr) * os->nr_pages);
	if (!os->trans_map)
		goto err_trans_map;
	memset(os->trans_map, 0, sizeof(struct openssd_addr) * os->nr_pages);

	// initial l2p is LTOP_EMPTY
	for (i = 0; i < os->nr_pages; i++)
		os->trans_map[i].addr = LTOP_EMPTY;

	os->rev_trans_map = vmalloc(sizeof(sector_t) * os->nr_pages);
	if (!os->rev_trans_map)
		goto err_rev_trans_map;

	os->per_bio_pool = mempool_create_slab_pool(16, _per_bio_cache);
	if (!os->per_bio_pool)
		goto err_dev_lookup;

	if (dm_get_device(ti, argv[0], dm_table_get_mode(ti->table), &os->dev))
		goto err_per_bio_pool;

	if (bdev_physical_block_size(os->dev->bdev) > EXPOSED_PAGE_SIZE) {
		ti->error = "dm-openssd: Got bad sector size. Device sector size is larged then the exposed";
		goto err_per_bio_pool;
	}
	os->sector_size = EXPOSED_PAGE_SIZE;
	os->nr_aps_per_pool = APS_PER_POOL;
	os->serialize_pool_access = SERIALIZE_POOL_ACCESS;

	// Simple round-robin strategy
	atomic_set(&os->next_write_ap, -1);

	os->lookup_ltop = openssd_lookup_ltop;
	os->lookup_ptol = openssd_lookup_ptol;
	os->map_ltop = openssd_alloc_map_ltop_rr;
	os->write_bio = openssd_write_bio_generic;
	os->read_bio = openssd_read_bio_generic;

	if (openssd_alloc_hint(os))
		goto err_per_bio_pool;

	DMINFO("Target sector size=%d", os->sector_size);
	DMINFO("Disk logical sector size=%d", bdev_logical_block_size(os->dev->bdev));
	DMINFO("Disk physical sector size=%d", bdev_physical_block_size(os->dev->bdev));
	DMINFO("Disk flash page size=%d", FLASH_PAGE_SIZE);

	os->ti = ti;
	ti->private = os;

	/* Initialize pools. */
	openssd_pool_init(os, ti);

	// FIXME: Clean up pool init on failure.
	os->kt_openssd = kthread_run(openssd_kthread, os, "kopenssd");
	if (!os->kt_openssd)
		goto err_per_bio_pool;

	if (openssd_init_hint(os))
		goto err_per_bio_pool; // possible mem leak from pool_init.

	DMINFO("allocated %lu physical pages (%lu KB)", os->nr_pages, os->nr_pages * os->sector_size / 1024);
	DMINFO("successful loaded");

	return 0;
err_per_bio_pool:
	mempool_destroy(os->per_bio_pool);
err_dev_lookup:
	vfree(os->rev_trans_map);
err_rev_trans_map:
	vfree(os->trans_map);
err_trans_map:
	kfree(os);
	ti->error = "dm-openssd: Cannot allocate openssd mapping context";
	return -ENOMEM;
}

static void openssd_dtr(struct dm_target *ti)
{
	struct openssd *os = (struct openssd *) ti->private;
	struct openssd_pool *pool;
	struct openssd_pool_block *block;
	int i, j;

	dm_put_device(ti, os->dev);

	ssd_for_each_pool(os, pool, i) {
		while (bio_list_peek(&pool->waiting_bios))
			flush_scheduled_work();
	}

	kthread_stop(os->kt_openssd);

	ssd_for_each_pool(os, pool, i) {
		pool_for_each_block(pool, block, j)
			percpu_ref_kill(&block->ref_count);
		kfree(pool->blocks);
	}

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
	.name = "openssd",
	.version = {0, 0, 1},
	.module	= THIS_MODULE,
	.ctr = openssd_ctr,
	.dtr = openssd_dtr,
	.map = openssd_map,
	.ioctl = openssd_ioctl,
	.status = openssd_status,
};

static int __init dm_openssd_init(void)
{
	_per_bio_cache = kmem_cache_create("openssd_per_bio_cache",
				sizeof(struct per_bio_data), 0, 0, NULL);
	if (!_per_bio_cache)
		return -ENOMEM;

	return dm_register_target(&openssd_target);
}

static void dm_openssd_exit(void)
{
	kmem_cache_destroy(_per_bio_cache);
	dm_unregister_target(&openssd_target);
}

module_init(dm_openssd_init);
module_exit(dm_openssd_exit);

MODULE_DESCRIPTION(DM_NAME "device-mapper openssd target");
MODULE_AUTHOR("Matias Bjørling <mb@silverwolf.dk>");
MODULE_LICENSE("GPL");
