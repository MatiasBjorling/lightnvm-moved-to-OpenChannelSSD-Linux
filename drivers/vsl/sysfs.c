#include <linux/openvsl.h>
#include <linux/sysfs.h>

#include "vsl.h"

static ssize_t vsl_attr_free_blocks_show(struct vsl_dev *vsl, char *buf)
{
	char *buf_start = buf;
	struct vsl_stor *stor = vsl->stor;
	struct vsl_pool *pool;
	unsigned int i;

	vsl_for_each_pool(stor, pool, i)
		buf += sprintf(buf, "%8u\t%u\n", i, pool->nr_free_blocks);

	return buf - buf_start;
}

static ssize_t vsl_attr_show(struct device *dev, char *page,
			      ssize_t (*fn)(struct vsl_dev *, char *))
{
	struct gendisk *disk = dev_to_disk(dev);
	struct vsl_dev *vsl = disk->private_data;

	return fn(vsl, page);
}

#define VSL_ATTR_RO(_name)						\
static ssize_t vsl_attr_##_name##_show(struct vsl_dev *, char *);	\
static ssize_t vsl_attr_do_show_##_name(struct device *d,		\
				struct device_attribute *attr, char *b)	\
{									\
	return vsl_attr_show(d, b, vsl_attr_##_name##_show);		\
}									\
static struct device_attribute vsl_attr_##_name =			\
	__ATTR(_name, S_IRUGO, vsl_attr_do_show_##_name, NULL);

VSL_ATTR_RO(free_blocks);

static struct attribute *vsl_attrs[] = {
	&vsl_attr_free_blocks.attr,
	NULL,
};

static struct attribute_group vsl_attribute_group = {
	.name = "vsl",
	.attrs = vsl_attrs,
};

void vsl_remove_sysfs(struct vsl_dev *vsl)
{
	struct device *dev;

	if (!vsl || !vsl->disk)
		return;

	dev = disk_to_dev(vsl->disk);
	sysfs_remove_group(&dev->kobj, &vsl_attribute_group);
}

int vsl_add_sysfs(struct vsl_dev *vsl)
{
	int ret;
	struct device *dev;

	if (!vsl || !vsl->disk)
		return 0;

	dev = disk_to_dev(vsl->disk);
	ret = sysfs_create_group(&dev->kobj, &vsl_attribute_group);
	if (ret)
		return ret;

	kobject_uevent(&dev->kobj, KOBJ_CHANGE);

	return 0;
}
