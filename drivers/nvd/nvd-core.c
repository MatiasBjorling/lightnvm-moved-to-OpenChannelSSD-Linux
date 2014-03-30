#include <linux/blkdev.h>
#include <linux/blk-mq.h>

#include <linux/nvdev.h>
#include "nvdev.h"

int nvd_queue_rq(struct blk_mq_hw_ctx *hctx, struct request *rq)
{
	struct rem_map *map = rq->special;
	return map->ops->remap_rq(hctx, rq);
}
EXPORT_SYMBOL(rem_queue_rq);

void nvd_complete_rq(struct request *rq)
{
	struct rem_map *map = rq->special;
	map->ops->complete_rq(struct request *rq);
}
EXPORT_SYMBOL(rem_complete_rq);

void nvd_end_rq(struct request *rq, int error)
{
	struct nvd_map *map = rq->special;
	map->ops->end_rq(rq, error);
}
EXPORT_SYMBOL(rem_end_rq);

struct nvd_map *rem_init_rq_queue(struct nvd_reg *reg, void *driver_data)
{

}
EXPORT_SYMBOL(rem_init_rq_queue);

void nvd_free_remap(struct nvd_map *m)
{

}
EXPORT_SYMBOL(rem_free_remap);
