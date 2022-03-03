/*
 * add standard char device interface for fbxwatchdog.
 */

/*
 * XXX: results are undefined if attemps are made to access watchdog
 * from char device interface and sysfs at the same time.
 */

#define PFX "fbxwatchdog_char: "

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/timer.h>
#include <linux/miscdevice.h>
#include <linux/watchdog.h>
#include "fbxwatchdog.h"

#include <asm/uaccess.h>

static struct fbxwatchdog *chardev_wdt;
static unsigned long chardev_users;
static unsigned long default_countdown = 60 * 1000;
static int expect_close;

/*
 * we support the WDIOF_MAGICCLOSE: is the user writes 'V' to the device,
 * the release method will stop the watchdog.
 */
static int
wdt_write(struct file *file, const char *__user buf, size_t len, loff_t *ppos)
{
	int i;

	if (!len)
		return 0;

	for (i = 0; i < len; ++i) {
		char c;

		if (get_user(c, buf + i))
			return -EFAULT;
		if (c == 'V')
			expect_close = 1;
	}
	if (len)
		chardev_wdt->countdown = default_countdown;
	return len;
}

static long
wdt_ioctl(struct file *file,
	  unsigned int cmd, unsigned long arg)
{
	static const struct watchdog_info winfo = {
		.options		= WDIOF_SETTIMEOUT | WDIOF_MAGICCLOSE |
					  WDIOF_KEEPALIVEPING,
		.firmware_version	= 0x42,
		.identity		= "fbxwatchdog",
	};
	int tmp;

	switch (cmd) {
	case WDIOC_GETSUPPORT:
		/*
		 * return watchdog information structure to userland.
		 */
		return copy_to_user((struct watchdog_info __user *)arg,
				    &winfo, sizeof (winfo)) ? -EFAULT: 0;

	case WDIOC_SETTIMEOUT:
		/*
		 * set watchdog timeout: if current countdown is
		 * higher than timeout, set countdown to timeout
		 * value.
		 */
		if (copy_from_user(&tmp, (void __user *) arg,
				   sizeof (tmp))) {
			return -EFAULT;
		}
		if (1000 * tmp < 0)
			return -EINVAL;
		default_countdown = 1000 * tmp;
		if (chardev_wdt->countdown > default_countdown)
			chardev_wdt->countdown = default_countdown;
		return 0;

	case WDIOC_GETTIMEOUT:
		/*
		 * get current timeout value.
		 */
		tmp = default_countdown / 1000;
		return copy_to_user((void __user *)arg, &tmp,
				    sizeof (tmp)) ? -EFAULT : 0;

	case WDIOC_KEEPALIVE:
		/*
		 * ping watchdog.
		 */
		chardev_wdt->countdown = default_countdown;
		return 0;

	case WDIOC_GETTIMELEFT:
		/*
		 * return current countdown value to userland.
		 */
		tmp = chardev_wdt->countdown / 1000;
		return copy_to_user((void __user *)arg, &tmp, sizeof (tmp)) ?
		  -EFAULT : 0;

	default:
		return -ENOIOCTLCMD;
	}
}

/*
 * called when remote process calls close(2) on watchdog fd or
 * exit(2).
 */
static int
wdt_release(struct inode *inode, struct file *file)
{
	unsigned long flags;

	if (expect_close && chardev_wdt->enabled) {
		spin_lock_irqsave(&chardev_wdt->lock, flags);
		chardev_wdt->enabled = 0;
		chardev_wdt->wdt_stop(chardev_wdt);
		spin_unlock_irqrestore(&chardev_wdt->lock, flags);
	} else
		printk(KERN_CRIT PFX "unexpected close: not stopping "
		       "watchdog.\n");
	chardev_users = 0;
	return 0;
}

/*
 * open watchdog device file: the test_and_set_bit enforces the fact
 * that only one process opens the watchdog device file as long as it
 * does not try to fork(2). dup(2)/dup2(2) might be problematic
 * too. thus, we assume that watchdogd will do "The right thing" and
 * won't try to do anything too fancy with the fd opened to
 * /dev/watchdog.
 */
static int wdt_open(struct inode *inode, struct file *file)
{
	unsigned long flags;

	if (test_and_set_bit(1, &chardev_users))
		return -EBUSY;

	expect_close = 0;

	/*
	 * watchdog is to be enabled when opened.
	 */
	if (!chardev_wdt->enabled) {
		spin_lock_irqsave(&chardev_wdt->lock, flags);
		chardev_wdt->enabled = 1;
		chardev_wdt->countdown = default_countdown;
		chardev_wdt->wdt_start(chardev_wdt);
		chardev_wdt->countdown_min = INT_MAX;
		spin_unlock_irqrestore(&chardev_wdt->lock, flags);
	}
	return 0;
}

static struct file_operations wdt_fops = {
	.owner		= THIS_MODULE,
	.open		= wdt_open,
	.write		= wdt_write,
	.unlocked_ioctl	= wdt_ioctl,
	.release	= wdt_release,
};

static struct miscdevice wdt_miscdev = {
	.minor		= WATCHDOG_MINOR,
	.name		= "watchdog",
	.fops		= &wdt_fops,
};

/*
 * add watchdog to the char interface. if we are already bound to a
 * watchdog, return 0, this is not a major no-no.
 */
int
fbxwatchdog_char_add(struct fbxwatchdog *wdt)
{
	int err;

	err = misc_register(&wdt_miscdev);
	if (err) {
		printk("unable to register misc device.\n");
		if (err == -EEXIST)
			return 0;
		return err;
	}
	chardev_wdt = wdt;
	return 0;
}

/*
 * if the watchdog is bound to the char device interface, unregister
 * the misc device and tell that we are no more bound to a
 * watchdog. otherwise, do nothing.
 */
void
fbxwatchdog_char_remove(struct fbxwatchdog *wdt)
{
	if (wdt != chardev_wdt)
		return ;
	misc_deregister(&wdt_miscdev);
	chardev_wdt = NULL;
}

EXPORT_SYMBOL(fbxwatchdog_char_add);
EXPORT_SYMBOL(fbxwatchdog_char_remove);
