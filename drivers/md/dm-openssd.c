/*
 * Copyright (C) 2012 Matias Bjørling.
 *
 * This file is released under the GPL.
 */

#include "dm-openssd.h"

#include <linux/device-mapper.h>
#include <linux/dm-io.h>
#include <linux/dm-kcopyd.h>
#include <linux/list.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>

/*----------------------------------------------------------------
 * OpenSSD target methods
 *--------------------------------------------------------------*/
static void openssd_dtr(struct dm_target *ti)
{
}

static int openssd_ctr(struct dm_target *ti, unsigned argc, char **argv)
{
	return 0;
}

static int openssd_map(struct dm_target *ti, struct bio *bio,
		    union map_info *map_context)
{
	return 0;
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
	.end_io = openssd_endio,
	.postsuspend = openssd_postsuspend,
	.status = openssd_status,
	.iterate_devices = openssd_iterate_devices,
	.io_hints = openssd_io_hints,
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

MODULE_DESCRIPTION(DM_NAME "device-mapper thin provisioning target");
MODULE_AUTHOR("Joe Thornber <dm-devel@redhat.com>");
MODULE_LICENSE("GPL");
