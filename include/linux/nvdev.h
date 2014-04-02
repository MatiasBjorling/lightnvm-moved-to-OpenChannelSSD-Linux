#ifndef NVDEV_H
#define NVDEV_H

#include <linux/blk-mq.h>

struct nv_queue {
	struct nvd_target *target;
	struct request_queue *blkq;
	struct blk_mq_ops blk_ops;
	void *driver_data;
};

typedef int (nvd_remap_fn)(struct nvd_map *map);
typedef void (nvd_end_rq_fn)(struct request *rq);
typedef int (nvd_rescan_fn)(struct nvd_map *map);
typedef int (*nvd_init_fn)(struct nvd_target *);
typedef void (*nvd_exit_fn)(struct nvd_target *);

struct nvd_target {
	/*
	 * Remap request
	 */
	nvd_remap_fn		*remap;

	/*
	 * End a remapped request
	 */
	nvd_end_rq_fn		*end_rq;

	/*
	 * Complete a remapped request
	 */
	nvd_complete_rq_fn		*complete_rq;

	/*
	 * Rescan information from a device.
	 */
	nvd_rescan_fn		*rescan_nvd;

	/*
	 * Module specific init/teardown
	 */
	nvd_init_fn		*init;
	nvd_exit_fn		*exit;

	/*
	 * For nvd internal use
	 */
	struct list_head	list;
};

struct nvd_reg {
	/* name of nv target module to initialize */
	const char		*target_name;
	/* minimum required version */
	unsigned int		version[3];
	unsigned int		flags;		/* NVD_F_* */
};

/* nvd-core.c */
int nvd_register_target(struct nvd_target *t);
void nvd_unregister_target(struct nvd_target *t);

#endif
