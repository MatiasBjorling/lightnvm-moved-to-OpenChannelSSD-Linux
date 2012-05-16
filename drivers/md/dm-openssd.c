/*
 * Copyright (C) 2012 Matias Bjørling.
 *
 * This file is released under the GPL.
 */

#include "dm-openssd.h"

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

struct dm_openssd {
	struct dm_dev *dev;

	struct dm_target *ti;

	struct dm_openssd_map *trans_map;
	struct dm_openssd_dev_conf dev_conf;
};

/*----------------------------------------------------------------
 * OpenSSD target methods
 *--------------------------------------------------------------*/
static void openssd_dtr(struct dm_target *ti)
{
	struct dm_openssd *os = (struct dm_openssd *) ti->private;

	dm_put_device(ti, os->dev);

	vfree(os->trans_map);
	kfree(os);
}

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

	// These does what? ( From dm-linear )
	ti->num_flush_requests = 1;
	ti->num_discard_requests = 1;

	os->ti = ti;
	ti->private = os;

	return 0;

bad:
	vfree(map);
	kfree(os);
	return -EINVAL;
}

static int openssd_map(struct dm_target *ti, struct bio *bio,
		    union map_info *map_context)
{
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
