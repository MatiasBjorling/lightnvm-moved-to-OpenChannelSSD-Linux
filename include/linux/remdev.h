#ifndef NVDEV_H
#define NVDEV_H

typedef int (remap_fn)(struct nvd_map *map);
typedef void (end_rq_fn)(struct request *rq);
typedef int (rescan_nvd_fn)(struct nvd_map *map);

struct nvd_ops {
	/*
	 * Remap request
	 */
	remap_fn		*remap;

	/*
	 * End a remapped request
	 */
	end_rq_fn		*end_rq;

	/*
	 * Complete a remapped request
	 */
	complete_rq_fn		*complete_rq;

	/*
	 * Rescan information from a device.
	 */
	rescan_nvd_fn		*rescan_nvd;
};

struct nvd_reg {
	struct nvd_ops		*ops;
	struct blk_mq_reg	*blk_mq_reg;
	unsigned int		flags;		/* REM_F_* */
};

#endif
