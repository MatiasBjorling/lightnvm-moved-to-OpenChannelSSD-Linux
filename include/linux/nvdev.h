#ifndef NVDEV_H
#define NVDEV_H

struct nv_queue {
	struct nvd_target_type *type;
	
};

typedef int (nvd_remap_fn)(struct nvd_map *map);
typedef void (nvd_end_rq_fn)(struct request *rq);
typedef int (nvd_rescan_fn)(struct nvd_map *map);
typedef int (*nvd_init_fn)(struct nvd_target *);
typedef void (*nvd_exit_fn)(struct nvd_target *);

struct nvd_target {
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
	struct nvd_target	*target;
	struct blk_mq_reg	*blk_mq_reg;
	unsigned int		flags;		/* REM_F_* */
};

/* nvd-core.c */
int nvd_register_target(struct nvd_target *t);
void nvd_unregister_target(struct nvd_target *t);
struct nvd_target *find_nvd_target(const char *name);

#endif
