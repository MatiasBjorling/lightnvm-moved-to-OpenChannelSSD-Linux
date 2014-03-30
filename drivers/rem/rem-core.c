#include <linux/blkdev.h>
#include <linux/blk-mq.h>

#include <linux/remdev.h>
#include "remdev.h"

int rem_queue_rq(struct blk_mq_hw_ctx *hctx, struct request *rq)
{
	struct rem_map *map = rq->special;
	return map->ops->remap(hctx, rq);
}

struct rem_map *rem_init_rq_remap(struct rem_reg *reg, void *driver_data)
{

}
EXPORT_SYMBOL(rem_init_rq_remap);

void rem_free_remap(struct rem_map *m)
{

}
EXPORT_SYMBOL(rem_free_remap);
