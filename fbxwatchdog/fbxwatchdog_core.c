#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/reboot.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/slab.h>

#include "fbxwatchdog.h"

#define SOFTTIMER_FREQ	(HZ / 10)

#define PFX "fbxwatchdog: "

static struct class *fbxwatchdog_class;

static ssize_t
show_enabled(struct device *dev,
	     struct device_attribute *attr, char *buf)
{
	struct fbxwatchdog *wdt;

	wdt = dev_get_drvdata(dev);
	if (!wdt) {
		printk(KERN_DEBUG "ignoring request to dead watchdog.\n");
		return -ENODEV;
	}

	return snprintf(buf, PAGE_SIZE, "%i\n", wdt->enabled);
}

/*
 * start/stop watchdog depending on the value of the first character
 * of buf. set countdown_min to a sane value.
 */
static ssize_t
store_enabled(struct device *dev,
	      struct device_attribute *attr, const char *buf, size_t size)
{
	struct fbxwatchdog *wdt;
	unsigned long flags;

	wdt = dev_get_drvdata(dev);
	if (!wdt) {
		printk(KERN_DEBUG "ignoring request to dead watchdog.\n");
		return -ENODEV;
	}

	if (size == 0)
		return 0;


	spin_lock_irqsave(&wdt->lock, flags);
	switch (*buf) {
	case '0':
		if (wdt->enabled) {
			wdt->enabled = 0;
			wdt->wdt_stop(wdt);
		}
		break;

	case '1':
		if (!wdt->enabled) {
			wdt->enabled = 1;
			wdt->wdt_start(wdt);
			wdt->countdown_min = INT_MAX;
		}
		break;

	default:
		break;
	}
	spin_unlock_irqrestore(&wdt->lock, flags);

	return size;
}

static ssize_t
show_countdown(struct device *dev,
	       struct device_attribute *attr, char *buf)
{
	struct fbxwatchdog *wdt;

	wdt = dev_get_drvdata(dev);
	if (!wdt) {
		printk(KERN_DEBUG "ignoring request to dead watchdog.\n");
		return -ENODEV;
	}

	return snprintf(buf, PAGE_SIZE, "%i\n", wdt->countdown);
}

/*
 * update watchdog countdown with the userland value given in buf.
 */
static ssize_t
store_countdown(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t size)
{
	struct fbxwatchdog *wdt;
	int countdown;
	char *ptr;

	wdt = dev_get_drvdata(dev);
	if (!wdt) {
		printk(KERN_DEBUG "ignoring request to dead watchdog.\n");
		return -ENODEV;
	}

	if (size == 0)
		return 0;

	ptr = kzalloc(size + 1, GFP_KERNEL);
	if (!ptr)
		return -ENOMEM;
	strlcpy(ptr, buf, size + 1);

	countdown = simple_strtoul(ptr, NULL, 10);
	wdt->countdown = countdown;
	kfree(ptr);

	return size;
}

static ssize_t
show_countdown_min(struct device *dev,
		   struct device_attribute *attr, char *buf)
{
	struct fbxwatchdog *wdt;

	wdt = dev_get_drvdata(dev);
	if (!wdt) {
		printk(KERN_DEBUG "ignoring request to dead watchdog.\n");
		return -ENODEV;
	}

	return snprintf(buf, PAGE_SIZE, "%i\n", wdt->countdown_min);
}

static struct device_attribute wdt_attributes[] = {
	__ATTR(enabled, 0600, show_enabled, store_enabled),
	__ATTR(countdown, 0600, show_countdown, store_countdown),
	__ATTR(countdown_min, 0400, show_countdown_min, NULL),
};

/*
 * software timer callback: decrement countdown and update
 * countdown_min if needed. this is called 10 times per second.
 */
static void fbxwatchdog_timer_cb(unsigned long data)
{
	struct fbxwatchdog *wdt;

	wdt = (struct fbxwatchdog *)data;

	if (wdt->enabled) {
		wdt->countdown -= jiffies_to_msecs(SOFTTIMER_FREQ);
		if (wdt->countdown < wdt->countdown_min)
			wdt->countdown_min = wdt->countdown;
	}

	wdt->timer.expires = jiffies + SOFTTIMER_FREQ;
	add_timer(&wdt->timer);
}

/*
 * called from half life interrupt handler, panic if countdown is too
 * low (ie if userland has not reset countdown to before it reached
 * 0).
 */
static void fbxwatchdog_halflife_cb(struct fbxwatchdog *wdt)
{
	if (wdt->countdown <= 0) {
		wdt->wdt_stop(wdt);
		panic("software fbxwatchdog triggered");
	}
}

/*
 * register a new watchdog device.
 */
int fbxwatchdog_register(struct fbxwatchdog *wdt)
{
	struct device *dev;
	int i = 0, err = 0;

	if (wdt == NULL)
		return -EFAULT;

	printk(KERN_INFO PFX "registering watchdog %s\n", wdt->name);

	dev = device_create(fbxwatchdog_class, NULL, 0, wdt, "%s", wdt->name);
	if (IS_ERR(dev)) {
		printk(KERN_ERR PFX "unable to allocate device.\n");
		err = PTR_ERR(dev);
		goto out_error;
	}
	wdt->dev = dev;

	for (i = 0; i < ARRAY_SIZE(wdt_attributes); i++) {
		err = device_create_file(dev, &wdt_attributes[i]);
		if (err)
			goto out_error;
	}

	/* start countdown soft timer */
	init_timer(&wdt->timer);
	wdt->timer.function = fbxwatchdog_timer_cb;
	wdt->timer.data = (unsigned long)wdt;
	wdt->timer.expires = jiffies + SOFTTIMER_FREQ;
	add_timer(&wdt->timer);

	spin_lock_init(&wdt->lock);

	wdt->cb = fbxwatchdog_halflife_cb;
	err = wdt->wdt_init(wdt);
	if (err) {
		printk(KERN_ERR PFX "unable to do low level init of "
		       "watchdog %s.\n", wdt->name);
		goto out_del_timer;
	}

#ifdef CONFIG_FREEBOX_WATCHDOG_CHAR
	err = fbxwatchdog_char_add(wdt);
	if (err) {
		printk(KERN_ERR PFX "unable to add %s to the fbxwatchdog char "
		       "device interface.\n", wdt->name);
		goto out_wdt_cleanup;
	}
#endif

	return 0;

#ifdef CONFIG_FREEBOX_WATCHDOG_CHAR
out_wdt_cleanup:
	wdt->wdt_cleanup(wdt);
#endif

out_del_timer:
	del_timer_sync(&wdt->timer);
out_error:
	if (wdt->dev) {
		for (; i >= 0; i--)
			device_remove_file(dev, &wdt_attributes[i]);
		device_unregister(dev);
	}
	return err;
}

int fbxwatchdog_unregister(struct fbxwatchdog *wdt)
{
	int i;

	printk(KERN_INFO PFX "registering watchdog %s\n", wdt->name);

	if (wdt->enabled) {
		unsigned long flags;

		printk(KERN_WARNING "removing enabled watchdog.\n");
		spin_lock_irqsave(&wdt->lock, flags);
		wdt->wdt_stop(wdt);
		spin_unlock_irqrestore(&wdt->lock, flags);
	}

#ifdef CONFIG_FREEBOX_WATCHDOG_CHAR
	fbxwatchdog_char_remove(wdt);
#endif
	wdt->wdt_cleanup(wdt);
	del_timer_sync(&wdt->timer);
	for (i = 0; i < ARRAY_SIZE(wdt_attributes); i++)
		device_remove_file(wdt->dev, &wdt_attributes[i]);
	device_unregister(wdt->dev);
	wdt->dev = NULL;
	return 0;
}

static int __init fbxwatchdog_init(void)
{
	printk(KERN_INFO PFX "2007, Freebox SA.\n");
	fbxwatchdog_class = class_create(THIS_MODULE, "fbxwatchdog");
	if (IS_ERR(fbxwatchdog_class))
		return PTR_ERR(fbxwatchdog_class);
	return 0;
}

static void __exit fbxwatchdog_exit(void)
{
	class_destroy(fbxwatchdog_class);
}


EXPORT_SYMBOL_GPL(fbxwatchdog_register);
EXPORT_SYMBOL_GPL(fbxwatchdog_unregister);

module_init(fbxwatchdog_init);
module_exit(fbxwatchdog_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nicolas Schichan <nschichan@freebox.fr>");
MODULE_DESCRIPTION("Freebox Watchdog Core - www.freebox.fr");
