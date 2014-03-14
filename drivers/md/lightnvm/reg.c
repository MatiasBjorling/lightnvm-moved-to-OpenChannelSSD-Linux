#include <linux/list.h>
#include <linux/sem.h>
#include "lightnvm.h"

static LIST_HEAD(_targets);
static DECLARE_RWSEM(_lock);

inline struct nvm_target_type *find_nvm_target_type(const char *name)
{
	struct nvm_target_type *t;

	list_for_each_entry(t, &_targets, list)
		if (!strcmp(name, t->name))
			return t;

	return NULL;
}

int nvm_register_target(struct nvm_target_type *t)
{
	int ret = 0;

	down_write(&_lock);
	if (find_nvm_target_type(t->name))
		ret = -EEXIST;
	else
		list_add(&t->list, &_targets);
	up_write(&_lock);
	return ret;
}

void nvm_unregister_target(struct nvm_target_type *t)
{
	if (!t)
		return;

	down_write(&_lock);
	list_del(&t->list);
	up_write(&_lock);
}

