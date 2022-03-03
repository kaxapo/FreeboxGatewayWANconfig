#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/err.h>
#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/fbxgpio_core.h>

#define PFX	"fbxgpio_core: "

/* #define DEBUG */
#ifdef DEBUG
#define dprint(Fmt, Arg...)	printk(PFX Fmt, Arg)
#else
#define dprint(Fmt, Arg...)	do { } while (0)
#endif

static struct class *fbxgpio_class;

/*
 * show direction in for gpio associated with class_device dev.
 */
static ssize_t show_direction(struct device *dev,
			      struct device_attribute *attr, char *buf)
{
	struct fbxgpio_pin *p;
	int dir, ret = 0;

	p = dev_get_drvdata(dev);

	if (p->ops->get_direction)
		dir = p->ops->get_direction(p->pin_num);
	else
		dir = p->direction;

	switch (dir) {
	case GPIO_DIR_IN:
		ret += sprintf(buf, "input\n");
		break;
	case GPIO_DIR_OUT:
		ret += sprintf(buf, "output\n");
		break;
	default:
		ret += sprintf(buf, "unknown\n");
		break;
	}
	return ret;
}

/*
 * store direction. return -EINVAL if direction string is bad. return
 * -EPERM if flag FBXGPIO_PIN_DIR_RW is set in flags.
 */
static ssize_t store_direction(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t size)
{
	int dir;
	struct fbxgpio_pin *p;
	int match_len = 0;
	int i;
	static const char *word_match[] = {
		[GPIO_DIR_IN] = "input",
		[GPIO_DIR_OUT] = "output",
	};

	if (*buf == ' ' || *buf == '\t' || *buf == '\r' || *buf == '\n')
		/* silently eat any spaces/tab/linefeed/carriagereturn */
		return 1;

	p = dev_get_drvdata(dev);
	if (!(p->flags & FBXGPIO_PIN_DIR_RW)) {
		dprint("pin %s direction is read only.\n", p->pin_name);
		return -EPERM;
	}
	dir = 0;
	for (i = 0; i < 2; ++i) {
		if (size >= strlen(word_match[i]) &&
		    !strncmp(buf, word_match[i], strlen(word_match[i]))) {
			dir = i;
			match_len = strlen(word_match[i]);
			break ;
		}
	}
	if (i == 2)
		return -EINVAL;

	p->ops->set_direction(p->pin_num, dir);
	return match_len;
}

/*
 * show input data for input gpio pins.
 */
static ssize_t show_datain(struct device *dev,
			   struct device_attribute *attr, char *buf)
{
	int val;
	struct fbxgpio_pin *p;

	p = dev_get_drvdata(dev);
	if (p->direction == GPIO_DIR_OUT)
		return -EINVAL;
	val = p->ops->get_datain(p->pin_num);

	if (p->flags & FBXGPIO_PIN_REVERSE_POL)
		val = 1 - val;
	return sprintf(buf, "%i\n", val);
}

/*
 * show output data for output gpio pins.
 */
static ssize_t show_dataout(struct device *dev,
			    struct device_attribute *attr, char *buf)
{
	int val;
	struct fbxgpio_pin *p;

	p = dev_get_drvdata(dev);
	if (p->direction == GPIO_DIR_IN)
		return -EINVAL;
	if (p->ops->get_dataout)
		val = p->ops->get_dataout(p->pin_num);
	else
		val = p->cur_dataout;

	if (p->flags & FBXGPIO_PIN_REVERSE_POL)
		val = 1 - val;
	return sprintf(buf, "%i\n", val);
}

/*
 * store new dataout value for output gpio pins.
 */
static ssize_t store_dataout(struct device *dev,
	    struct device_attribute *attr, const char *buf, size_t size)
{
	int val;
	struct fbxgpio_pin *p;

	if (*buf == ' ' || *buf == '\t' || *buf == '\r' || *buf == '\n')
		/* silently eat any spaces/tab/linefeed/carriagereturn */
		return 1;

	p = dev_get_drvdata(dev);

	if (p->direction != GPIO_DIR_OUT)
		return -EINVAL;

	switch (*buf) {
	case '0':
		val = 0;
		break ;
	case '1':
		val = 1;
		break ;
	default:
		return -EINVAL;
	}

	p->cur_dataout = val;

	if (p->flags & FBXGPIO_PIN_REVERSE_POL)
		val = 1 - val;
	p->ops->set_dataout(p->pin_num, val);
	return 1;
}

/*
 * show pin number associated with gpio pin.
 */
static ssize_t show_pinnum(struct device *dev,
			   struct device_attribute *attr, char *buf)
{
	struct fbxgpio_pin *p;

	p = dev_get_drvdata(dev);
	return sprintf(buf, "%i\n", p->pin_num);
}

/*
 * attribute list associated with each class device.
 */
static struct device_attribute gpio_attributes[] = {
	__ATTR(direction, 0600, show_direction, store_direction),
	__ATTR(data_in,   0400, show_datain, NULL),
	__ATTR(data_out,  0600, show_dataout, store_dataout),
	__ATTR(pin_num,   0400, show_pinnum, NULL),
};

static int fbxgpio_register_pin(struct platform_device *ppdev,
				struct fbxgpio_pin *pin)
{
	struct device *dev;
	int i, ret;

	dprint("registering pin %s\n", pin->pin_name);

	/* ensure ops is valid */
	if (!pin->ops) {
		printk(KERN_ERR PFX "no operation set for pin %s\n",
		       pin->pin_name);
		return -EINVAL;
	}

	dev = device_create(fbxgpio_class, &ppdev->dev, 0, pin,
			    "%s", pin->pin_name);
	if (IS_ERR(dev))
		return PTR_ERR(dev);

	for (i = 0; i < ARRAY_SIZE(gpio_attributes); i++) {
		ret = device_create_file(dev, &gpio_attributes[i]);
		if (ret)
			goto err_out;
	}

	/* ensure pin direction matches hardware state */
	if (pin->ops->get_direction &&
	    pin->direction != pin->ops->get_direction(pin->pin_num)) {
		printk(KERN_WARNING PFX "pin %s default direction does not "
		       "match current hardware state, fixing.\n",
		       pin->pin_name);
		pin->ops->set_direction(pin->pin_num, pin->direction);
	}
	pin->dev = dev;
	return 0;

err_out:
	for (; i >= 0; i--)
		device_remove_file(dev, &gpio_attributes[i]);
	device_unregister(dev);
	return ret;
}

static void fbxgpio_unregister_pin(struct fbxgpio_pin *pin)
{
	struct device *dev;
	int i;

	dprint("unregistering pin %s\n", pin->pin_name);
	dev = pin->dev;
	pin->dev = NULL;

	for (i = 0; i < ARRAY_SIZE(gpio_attributes); i++)
		device_remove_file(dev, &gpio_attributes[i]);
	device_unregister(dev);
}

static int fbxgpio_platform_probe(struct platform_device *pdev)
{
	struct fbxgpio_pin *p;
	int err = 0;

	p = pdev->dev.platform_data;
	while (p->pin_name) {
		err = fbxgpio_register_pin(pdev, p);
		if (err)
			return err;
		++p;
	}
	return 0;
}

static int fbxgpio_platform_remove(struct platform_device *pdev)
{
	struct fbxgpio_pin *p;

	p = pdev->dev.platform_data;
	while (p->pin_name) {
		fbxgpio_unregister_pin(p);
		++p;
	}
	return 0;
}

static struct platform_driver fbxgpio_platform_driver =
{
	.probe	= fbxgpio_platform_probe,
	.remove	= fbxgpio_platform_remove,
	.driver	= {
		.name	= "fbxgpio",
	}
};

static int __init fbxgpio_init(void)
{
	int ret;

	fbxgpio_class = class_create(THIS_MODULE, "fbxgpio");
	if (IS_ERR(fbxgpio_class))
		return PTR_ERR(fbxgpio_class);

	ret = platform_driver_register(&fbxgpio_platform_driver);
	if (ret) {
		printk(KERN_ERR PFX "unable to register fbxgpio driver.\n");
		class_destroy(fbxgpio_class);
		return ret;
	}
	return 0;
}

static void __exit fbxgpio_exit(void)
{
	platform_driver_unregister(&fbxgpio_platform_driver);
	class_destroy(fbxgpio_class);
}

subsys_initcall(fbxgpio_init);
module_exit(fbxgpio_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nicolas Schichan <nicolas.schichan@freebox.fr>");
