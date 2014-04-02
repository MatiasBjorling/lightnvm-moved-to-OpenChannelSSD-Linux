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

struct nvd_map *nvd_init_queue(struct nvd_reg *reg,
				  struct blk_mq_reg *blk_reg, void *driver_data)
{
	struct nv_queue *nvq;

	if (!reg || !reg->target_name || !blk_reg)
		return ERR_PTR(-EINVAL);

	if (nvd_find_target(reg->target_name))
		return ERR_PTR(-EINVAL);

	nvq = kmalloc(sizeof(struct nvdev), GFP_ATOMIC);
	if (!nvq)
		return ERR_PTR(-ENOMEM);

	nvq->target = reg->target;
	nvq->driver_data = driver_data;

	/* redirect blk calls to shim layer before driver */


	nvq->blkq = blk_mq_init_queue(blk_reg, nv);
	if (!nvq->blkq)
		goto fail_blk_queue;

	return nvq->blkq;
}
EXPORT_SYMBOL(nvd_init_queue);

void nvd_free_remap(struct nvd_map *m)
{

}
EXPORT_SYMBOL(nvd_free_remap);

static int nvd_remap_noop(struct blk_mq_hw_ctx *hctx, struct request *rq)
{
	struct nvd_map *map = rq->special;
	return map->ops->remap_rq(hctx, rq);
}

static void nvd_end_rq_noop(struct request *rq, int error)
{
	struct nvd_map *map = rq->special;
	map->ops->end_rq(rq, error);
}

static struct nvd_target *nvd_target_noop {
	.remap = nvd_remap_noop,
	.end_rq = nvd_end_rq_noop,
};

static struct nvd_reg nvd_reg_noop {
	.target_name = "noop",
	.version = {1, 0, 0},
};

static int __init nvd_init(void)
{
	return nvd_register_target(&nvd_target_noop);
}

static int __exit nvd_exit(void)
{
	nvd_unregister_target(&nvd_target_noop);
}

module_init(nvd_mod_init);
module_init(nvd_mod_exit);

MODULE_DESCRIPTION("Non-Volatile Device Layer");
MODULE_AUTHOR("Matias Bjorling <m@bjorling.me>");
MODULE_LICENSE("GPL");
