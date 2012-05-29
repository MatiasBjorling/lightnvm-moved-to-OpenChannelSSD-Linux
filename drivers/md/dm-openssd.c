/*
 * Copyright (C) 2012 Matias Bjørling.
 *
 * This file is released under the GPL.
 *
 * Todo
 *
 * - Implement translation mapping from logical to physical flash pages
 * - Implement garbage collection
 * - Implement fetching of bad pages from flash
 *
 */

#include "dm-openssd.h"
#include "dm-openssd-pool.h"

#include <linux/device-mapper.h>
#include <linux/dm-io.h>
#include <linux/dm-kcopyd.h>
#include <linux/blkdev.h>
#include <linux/list.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>

struct dm_openssd_dev_conf {
	unsigned short int block_size; /* the number of flash pages per block */
	unsigned short int page_size;  /* the flash page size in bytes */
	unsigned int num_blocks;	   /* the number of blocks addressable by the mapped SSD. */
};

struct dm_openssd_map {
	long logical;
	long physical;
};

/* Pool descriptions */
struct dm_openssd_pool_blocks {
	unsigned int block_id;
	unsigned short int next_write;

	struct list_head list;
};

struct dm_openssd_pool {
	unsigned int start_block; /* References a physical start block */
	unsigned int end_block;   /* References a physical end block */

	/* Derived value from end_block - start_block. */
	unsigned int size;

	struct dm_openssd_pool_blocks free;
};


/* Main structure */
struct dm_openssd {
	struct dm_dev *dev;

	struct dm_target *ti;

	struct dm_openssd_map *trans_map;
	struct dm_openssd_dev_conf dev_conf;

	struct dm_openssd_pool *pools;
};

static void dm_openssd_pool_set_limits(struct dm_openssd_pool *pool, unsigned int start_block, unsigned int end_block)
{
	int i;
	struct dm_openssd_pool_blocks * blocks;

	INIT_LIST_HEAD(&pool->free.list);

	pool->start_block = start_block;
	pool->end_block = end_block;

	pool->size = end_block - start_block;

	blocks = kmalloc(sizeof(struct dm_openssd_pool_blocks) * pool->size, GFP_KERNEL);

	for (i=0;i<pool->size;i++)
	{
		blocks[i].block_id = start_block + i;
		list_add(&(blocks[i].list), &(pool->free.list));
	}
}

static unsigned short int nextpage_pool_id;

static struct dm_openssd_pool_blocks * dm_openssd_get_next_page(struct dm_openssd *os)
{

}

static int dm_openssd_pool_init(struct dm_openssd *os, struct dm_target *ti)
{
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
	 */
	const unsigned int CHIP_COUNT= 8;

	os->pools = kmalloc(sizeof(struct dm_openssd_pool) * CHIP_COUNT, GFP_KERNEL);
	if (os->pools == NULL) {
		ti->error = "dm-openssd: Cannot allocate openssd pools";
		return -ENOMEM;
	}

	dm_openssd_pool_set_limits(&os->pools[0],   1, 100);
	dm_openssd_pool_set_limits(&os->pools[1], 101, 200);
	dm_openssd_pool_set_limits(&os->pools[2], 201, 300);
	dm_openssd_pool_set_limits(&os->pools[3], 301, 400);
	dm_openssd_pool_set_limits(&os->pools[4], 401, 500);
	dm_openssd_pool_set_limits(&os->pools[5], 501, 600);
	dm_openssd_pool_set_limits(&os->pools[6], 601, 700);
	dm_openssd_pool_set_limits(&os->pools[7], 701, 800);

	return 0;
}

/*----------------------------------------------------------------
 * OpenSSD target methods
 *
 * ctr - Constructor
 * dtr - Destructor
 * map - Maps and execute a given IO.
 *--------------------------------------------------------------*/

/*
 * Accepts an OpenSSD-backed block-device. The OpenSSD device should run the
 * corresponding physical firmware that exports the flash as physical without any
 * mapping and garbage collection as it will be taken care of.
 */
static int openssd_ctr(struct dm_target *ti, unsigned argc, char **argv)
{
	struct dm_openssd *os;
	struct dm_openssd_map *map;

	// Which device it should map onto?

	if (argc != 1) {
		ti->error = "Only argument for block device allowed.";
		return -EINVAL;
	}

	os = kmalloc(sizeof(*os), GFP_KERNEL);
	if (os == NULL) {
		ti->error = "dm-openssd: Cannot allocate openssd context";
		return -ENOMEM;
	}

	map = vmalloc(sizeof(*map)*512*512*16); /* Remove constant with number of logical to
									  physical address mappings that should be stored. */
	if (map == NULL) {
		ti->error = "dm-openssd: Cannot allocate openssd mapping context";
		kfree(os);
		return -ENOMEM;
	}

	if (dm_get_device(ti, argv[0], dm_table_get_mode(ti->table), &os->dev)) {
		ti->error = "dm-openssd: Device lookup failed";
		goto bad;
	}

    // These do what? ( From dm-linear )
	ti->num_flush_requests = 1;
	ti->num_discard_requests = 1;

	os->ti = ti;
	ti->private = os;

	/* Initialize pools. */
	dm_openssd_pool_init(os, ti);


	return 0;

bad:
	vfree(map);
	kfree(os);
	return -EINVAL;
}

static void openssd_dtr(struct dm_target *ti)
{
	struct dm_openssd *os = (struct dm_openssd *) ti->private;

	dm_put_device(ti, os->dev);

	vfree(os->trans_map);
	kfree(os);
}

static int openssd_map(struct dm_target *ti, struct bio *bio,
		    union map_info *map_context)
{

	printk("Accessing: %lu size: %u\n", bio->bi_sector, bio->bi_size);
	bio->bi_sector = 1234;
	printk("Accessing2: %lu size: %u\n", bio->bi_sector, bio->bi_size);

	switch(bio_rw(bio)) {
	case READ:
		zero_fill_bio(bio);
		break;
	case READA:
		/* readahead of null bytes only wastes buffer cache */
		return -EIO;
	case WRITE:
		/* writes get silently dropped */
		break;
	}

	bio_endio(bio, 0);

	/* accepted bio, don't make new request */
	return DM_MAPIO_SUBMITTED;
}

static int openssd_endio(struct dm_target *ti,
		      struct bio *bio, int err,
		      union map_info *map_context)
{
	return 0;
}

static void openssd_postsuspend(struct dm_target *ti)
{

}

static int openssd_status(struct dm_target *ti, status_type_t type,
		       char *result, unsigned maxlen)
{
	return 0;
}

static int openssd_iterate_devices(struct dm_target *ti,
				iterate_devices_callout_fn fn, void *data)
{
	return 0;
}

static void openssd_io_hints(struct dm_target *ti, struct queue_limits *limits)
{

}

static struct target_type openssd_target = {
	.name = "openssd",
	.version = {0, 0, 1},
	.module	= THIS_MODULE,
	.ctr = openssd_ctr,
	.dtr = openssd_dtr,
	.map = openssd_map,
	//.end_io = openssd_endio,
	//.postsuspend = openssd_postsuspend,
	//.status = openssd_status,
	//.iterate_devices = openssd_iterate_devices,
	//.io_hints = openssd_io_hints,
};

static int __init dm_openssd_init(void)
{
	int r;

	r = dm_register_target(&openssd_target);

	return r;
}

static void dm_openssd_exit(void)
{
	dm_unregister_target(&openssd_target);
}

module_init(dm_openssd_init);
module_exit(dm_openssd_exit);

MODULE_DESCRIPTION(DM_NAME "device-mapper openssd target");
MODULE_AUTHOR("Matias Bjørling <mb@silverwolf.dk>");
MODULE_LICENSE("GPL");
