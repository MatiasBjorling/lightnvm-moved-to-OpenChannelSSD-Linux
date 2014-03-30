#ifndef REMDEV_H
#define REMDEV_H

typedef int (remap_fn)(struct rem_map *map);

struct rem_ops {
	/*
	 * Remap request
	 */
	remap_fn		*remap;
};

struct rem_reg {
	struct rem_ops		*ops;
	struct blk_mq_reg	*blk_mq_reg;
	unsigned int flags;			/* REM_F_* */
};


#endif
