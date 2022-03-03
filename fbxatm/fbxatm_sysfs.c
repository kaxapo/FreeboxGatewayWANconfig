#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kobject.h>
#include <linux/stat.h>
#include <linux/fbxatm_dev.h>
#include "fbxatm_priv.h"

#define to_fbxatm_dev(cldev) container_of(cldev, struct fbxatm_dev, dev)

static ssize_t show_ifindex(struct device *dev,
			  struct device_attribute *attr, char *buf)
{
	struct fbxatm_dev *adev = to_fbxatm_dev(dev);
	return sprintf(buf, "%d\n", adev->ifindex);
}

static ssize_t show_link_state(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct fbxatm_dev *adev = to_fbxatm_dev(dev);
	return sprintf(buf, "%d\n",
		       test_bit(FBXATM_DEV_F_LINK_UP, &adev->dev_flags) ?
		       1 : 0);
}

static ssize_t show_link_rate_us(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	struct fbxatm_dev *adev = to_fbxatm_dev(dev);
	return sprintf(buf, "%d\n", adev->link_rate_us);
}

static ssize_t show_link_rate_ds(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	struct fbxatm_dev *adev = to_fbxatm_dev(dev);
	return sprintf(buf, "%d\n", adev->link_rate_ds);
}

static ssize_t show_max_priority(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	struct fbxatm_dev *adev = to_fbxatm_dev(dev);
	return sprintf(buf, "%d\n", adev->max_priority);
}

static ssize_t show_max_rx_priority(struct device *dev,
				    struct device_attribute *attr, char *buf)
{
	struct fbxatm_dev *adev = to_fbxatm_dev(dev);
	return sprintf(buf, "%d\n", adev->max_rx_priority);
}

static DEVICE_ATTR(ifindex, S_IRUGO, show_ifindex, NULL);
static DEVICE_ATTR(link_state, S_IRUGO, show_link_state, NULL);
static DEVICE_ATTR(link_rate_us, S_IRUGO, show_link_rate_us, NULL);
static DEVICE_ATTR(link_rate_ds, S_IRUGO, show_link_rate_ds, NULL);
static DEVICE_ATTR(max_priority, S_IRUGO, show_max_priority, NULL);
static DEVICE_ATTR(max_rx_priority, S_IRUGO, show_max_rx_priority, NULL);

static struct device_attribute *fbxatm_attrs[] = {
	&dev_attr_ifindex,
	&dev_attr_link_state,
	&dev_attr_link_rate_us,
	&dev_attr_link_rate_ds,
	&dev_attr_max_priority,
	&dev_attr_max_rx_priority,
};

static int fbxatm_uevent(struct device *dev, struct kobj_uevent_env *env)
{
	struct fbxatm_dev *adev;

	if (!dev)
		return -ENODEV;

	adev = to_fbxatm_dev(dev);
	if (!adev)
		return -ENODEV;

	if (add_uevent_var(env, "NAME=%s", adev->name))
		return -ENOMEM;

	if (add_uevent_var(env, "IFINDEX=%u", adev->ifindex))
		return -ENOMEM;

	if (add_uevent_var(env, "LINK=%u",
			   test_bit(FBXATM_DEV_F_LINK_UP, &adev->dev_flags) ?
			   1 : 0))
		return -ENOMEM;

	return 0;
}

static void fbxatm_release(struct device *dev)
{
	struct fbxatm_dev *adev = to_fbxatm_dev(dev);
	__fbxatm_free_device(adev);
}

static struct class fbxatm_class = {
	.name		= "fbxatm",
	.dev_release	= fbxatm_release,
	.dev_uevent	= fbxatm_uevent,
};

void fbxatm_dev_change_sysfs(struct fbxatm_dev *adev)
{
	struct device *dev = &adev->dev;

	kobject_uevent_env(&dev->kobj, KOBJ_CHANGE, NULL);
}

int fbxatm_register_dev_sysfs(struct fbxatm_dev *adev)
{
	struct device *dev = &adev->dev;
	int i, j, ret;

	dev->class = &fbxatm_class;
	dev_set_name(dev, "%s", adev->name);
	ret = device_register(dev);
	if (ret < 0)
		return ret;

	for (i = 0; i < ARRAY_SIZE(fbxatm_attrs); i++) {
		ret = device_create_file(dev, fbxatm_attrs[i]);
		if (ret)
			goto err;
	}
	return 0;

err:
	for (j = 0; j < i; j++)
		device_remove_file(dev, fbxatm_attrs[j]);
	device_del(dev);
	return ret;
}

void fbxatm_unregister_dev_sysfs(struct fbxatm_dev *adev)
{
	struct device *dev = &adev->dev;
	device_del(dev);
}

int __init fbxatm_sysfs_init(void)
{
	return class_register(&fbxatm_class);
}

void fbxatm_sysfs_exit(void)
{
	class_unregister(&fbxatm_class);
}
