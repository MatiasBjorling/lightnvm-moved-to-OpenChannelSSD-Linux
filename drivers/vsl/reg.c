#include <linux/list.h>
#include <linux/sem.h>
#include "vsl.h"

static LIST_HEAD(_targets);
static DECLARE_RWSEM(_lock);

inline struct vsl_target_type *find_vsl_target_type(const char *name)
{
	struct vsl_target_type *t;

	list_for_each_entry(t, &_targets, list)
		if (!strcmp(name, t->name))
			return t;

	return NULL;
}

int vsl_register_target(struct vsl_target_type *t)
{
	int ret = 0;

	down_write(&_lock);
	if (find_vsl_target_type(t->name))
		ret = -EEXIST;
	else
		list_add(&t->list, &_targets);
	up_write(&_lock);
	return ret;
}

void vsl_unregister_target(struct vsl_target_type *t)
{
	if (!t)
		return;

	down_write(&_lock);
	list_del(&t->list);
	up_write(&_lock);
}

