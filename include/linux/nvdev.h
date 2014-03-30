#ifndef NVDEV_H
#define NVDEV_H

#include <linux/blk-mq.h>

struct nv_queue {
	struct nvd_target *target;

	struct request_queue *q;
	struct request_queue *admin_q;

	struct blk_mq_ops blk_ops;

	void *driver_data;
	void *target_data;

	unsigned int per_rq_offset;
};

typedef int (nvd_remap_fn)(struct nvd_map *map);
typedef void (nvd_end_rq_fn)(struct request *rq);
typedef int (nvd_rescan_fn)(struct nvd_map *map);
typedef int (*nvd_init_fn)(struct nvd_target *);
typedef void (*nvd_exit_fn)(struct nvd_target *);

struct nvd_target {
	/* name of nv target module to initialize */
	const char		*name;
	unsigned int		version[3];
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
	nvd_complete_rq_fn	*complete_rq;

	/*
	 * Probe information from a device.
	 */
	nvd_probe_fn		*probe_nvd;

	/*
	 * Module specific init/teardown
	 */
	nvd_init_fn		*ctr;
	nvd_exit_fn		*dtr;

	/*
	 * Device driver hooks
	 */
	struct blk_mq_ops	*dev_ops;

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
