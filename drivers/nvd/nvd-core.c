#include <linux/blkdev.h>
#include <linux/blk-mq.h>

#include <linux/nvdev.h>
#include "nvdev.h"

static LIST_HEAD(_targets);
static DECLARE_RWSEM(_lock);

inline struct nvd_target_type *nvd_find_target(const char *name)
{
	struct nvd_target_type *t;

	list_for_each_entry(t, &_targets, list)
		if (!strcmp(name, t->name))
			return t;

	return NULL;
}
EXPORT_SYMBOL(nvd_find_target);

int nvd_register_target(struct nvd_target_type *t)
{
	int ret = 0;

	down_write(&_lock);
	if (find_nvd_target_type(t->name))
		ret = -EEXIST;
	else
		list_add(&t->list, &_targets);
	up_write(&_lock);
	return ret;
}
EXPORT_SYMBOL(nvd_register_target);

void nvd_unregister_target(struct nvd_target_type *t)
{
	if (!t)
		return;

	down_write(&_lock);
	list_del(&t->list);
	up_write(&_lock);
}
EXPORT_SYMBOL(nvd_unregister_target);

int nvd_queue_rq(struct blk_mq_hw_ctx *hctx, struct request *rq)
{
	struct nvd_map *map = rq->special;
	return map->ops->remap_rq(hctx, rq);
}
EXPORT_SYMBOL(nvd_queue_rq);

void nvd_complete_rq(struct request *rq)
{
	struct rem_map *map = rq->special;
	map->ops->complete_rq(struct request *rq);
}
EXPORT_SYMBOL(nvd_complete_rq);

void nvd_end_rq(struct request *rq, int error)
{
	struct nvd_map *map = rq->special;
	map->ops->end_rq(rq, error);
}
EXPORT_SYMBOL(nvd_end_rq);

struct nvd_map *nvd_init_rq_queue(struct nvd_reg *reg, void *driver_data)
{
	
}
EXPORT_SYMBOL(nvd_init_rq_queue);

void nvd_free_remap(struct nvd_map *m)
{

}
EXPORT_SYMBOL(nvd_free_remap);
