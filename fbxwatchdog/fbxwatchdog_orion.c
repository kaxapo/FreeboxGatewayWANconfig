#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/clk.h>

#include "fbxwatchdog.h"

struct fbxwatchdog_orion_priv {
	struct clk		*clk;
	unsigned int		tclk;
	void __iomem		*wdt_base;
	void __iomem		*rstout_base;
	struct timer_list	half_life_timer;
};

/*
 * Watchdog timer block registers.
 */
#define RSTOUTn_MASK		(0x0108)
#define TIMER_CTRL		(0x0000)
#define  WDT_EN			0x0010
#define WDT_COUNTER		(0x0024)

#define WDT_MAX_CYCLE_COUNT	0xffffffff
#define WDT_IN_USE		0
#define WDT_OK_TO_CLOSE		1

#define WDT_RESET_OUT_EN	BIT(1)

static u32 read_rstout_mask(struct fbxwatchdog_orion_priv *priv)
{
	return readl(priv->rstout_base);
}

static void write_rstout_mask(struct fbxwatchdog_orion_priv *priv, u32 val)
{
	writel(val, priv->rstout_base);
}

static u32 read_wdt_timer_ctrl(struct fbxwatchdog_orion_priv *priv)
{
	return readl(priv->wdt_base + TIMER_CTRL);
}

static void write_wdt_timer_ctrl(struct fbxwatchdog_orion_priv *priv, u32 val)
{
	writel(val, priv->wdt_base + TIMER_CTRL);
}

static void write_wdt_counter(struct fbxwatchdog_orion_priv *priv, u32 val)
{
	writel(val, priv->wdt_base + WDT_COUNTER);
}

/*
 * orion does not trigger interrupts each times the watchdog reaches
 * the half of it's count down. we emulate this behaviour using a
 * linux timer that fires every 500 msec.
 */
static void
half_life_timer_cb(unsigned long data)
{
	struct fbxwatchdog *wdt;
	struct fbxwatchdog_orion_priv *priv;
	unsigned long flags;

	wdt = (struct fbxwatchdog *)data;
	priv = wdt->priv;

	spin_lock_irqsave(&wdt->lock, flags);

	/* reload counter */
	write_wdt_counter(priv, priv->tclk * 10);

	if (wdt->cb)
		wdt->cb(wdt);

	priv->half_life_timer.expires = jiffies + HZ / 2;
	add_timer(&priv->half_life_timer);

	spin_unlock_irqrestore(&wdt->lock, flags);
}

/*
 * setup half life timer.
 */
static int orion_wdt_init(struct fbxwatchdog *wdt)
{
	struct fbxwatchdog_orion_priv *priv;

	priv = wdt->priv;
	init_timer(&priv->half_life_timer);
	priv->half_life_timer.function = half_life_timer_cb;
	priv->half_life_timer.data = (unsigned long)wdt;
	return 0;
}

static int orion_wdt_cleanup(struct fbxwatchdog *wdt)
{
	return 0;
}

static int orion_wdt_start(struct fbxwatchdog *wdt)
{
	struct fbxwatchdog_orion_priv *priv;
	uint32_t val;

	dev_info(wdt->dev, "starting watchdog ...\n");

	priv = wdt->priv;
	val = read_wdt_timer_ctrl(priv);
	if (val & WDT_EN) {
		dev_warn(wdt->dev, "watchdog has been enabled by "
			 "bootloader.!\n");
		/* disable it */
		val &= ~WDT_EN;
		write_wdt_timer_ctrl(priv, val);
	}

	/* watchdog will blow up after 10 seconds if not refreshed */
	write_wdt_counter(priv, priv->tclk * 10);

	/* enable it */
	val = read_wdt_timer_ctrl(priv);
	val |= WDT_EN;
	write_wdt_timer_ctrl(priv, val);

	/* enable reset on watchdog */
	val = read_rstout_mask(priv);
	val |= WDT_RESET_OUT_EN;
	write_rstout_mask(priv, val);

	/* will fire every 500 ms */
	priv->half_life_timer.expires = jiffies + HZ / 2;
	add_timer(&priv->half_life_timer);

	return 0;
}

int orion_wdt_stop(struct fbxwatchdog *wdt)
{
	struct fbxwatchdog_orion_priv *priv;
	uint32_t val;

	dev_info(wdt->dev, "stopping watchdog ...\n");

	priv = wdt->priv;
	del_timer_sync(&priv->half_life_timer);

	/* disable it */
	val = read_wdt_timer_ctrl(priv);
	val &= ~WDT_EN;
	write_wdt_timer_ctrl(priv, val);

	/* disable reset on watchdog */
	val = read_rstout_mask(priv);
	val |= WDT_RESET_OUT_EN;
	write_rstout_mask(priv, val);

	return 0;
}

static int fbxwatchdog_platform_probe(struct platform_device *pdev)
{
	struct fbxwatchdog_orion_priv *priv = NULL;
	struct fbxwatchdog *wdt;
	struct clk *clk;
	struct resource *r_wdt, *r_rstout;
	int err = 0;

	clk = devm_clk_get(&pdev->dev, NULL);
	if (IS_ERR(clk)) {
		dev_err(&pdev->dev, "Orion Watchdog missing clock\n");
		return -ENODEV;
	}
	clk_prepare_enable(clk);

	r_wdt = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	r_rstout = platform_get_resource(pdev, IORESOURCE_MEM, 1);

	if (!r_rstout || !r_wdt) {
		dev_err(&pdev->dev, "Orion Watchdog missing resource.\n");
		return -ENODEV;

	}

	wdt = devm_kzalloc(&pdev->dev, sizeof (*wdt), GFP_KERNEL);
	if (!wdt) {
		dev_err(&pdev->dev, "unable allocate memory for watchdog.\n");
		err = -ENOMEM;
		goto out_error;
	}

	priv = devm_kzalloc(&pdev->dev, sizeof (*priv), GFP_KERNEL);
	if (!priv) {
		dev_err(&pdev->dev, "unable to allocate memory for private "
		       "structure.\n");
		err = -ENOMEM;
		goto out_error;
	}

	wdt->priv = priv;
	wdt->name = pdev->name;

	wdt->wdt_init = orion_wdt_init;
	wdt->wdt_cleanup = orion_wdt_cleanup;
	wdt->wdt_start = orion_wdt_start;
	wdt->wdt_stop = orion_wdt_stop;

	priv->wdt_base = devm_ioremap_resource(&pdev->dev, r_wdt);
	if (!priv->wdt_base) {
		dev_err(&pdev->dev, "unable to ioremap watchdog registers.");
		err = -ENOMEM;
		goto out_error;
	}

	priv->rstout_base = devm_ioremap_resource(&pdev->dev, r_rstout);
	if (!priv->rstout_base) {
		dev_err(&pdev->dev, "unable to ioremap rstou mask register.");
		err = -ENOMEM;
		goto out_error;
	}

	priv->tclk = clk_get_rate(clk);
	priv->clk = clk;
	dev_notice(&pdev->dev, "TCLK rate is %d Mhz.\n", priv->tclk / 1000000);


	err = fbxwatchdog_register(wdt);
	if (err) {
		dev_err(&pdev->dev, "unable to register watchdog %s\n",
			wdt->name);
		goto out_error;
	}

	platform_set_drvdata(pdev, wdt);

	return 0;

 out_error:
	clk_disable_unprepare(clk);
	return err;
}

/*
 * unregister and free memory allocated by the probe function.
 */
static int
fbxwatchdog_platform_remove(struct platform_device *pdev)
{
	struct fbxwatchdog *wdt;
	struct fbxwatchdog_orion_priv *priv;

	wdt = platform_get_drvdata(pdev);
	if (!wdt) {
		BUG();
		return -ENODEV;
	}

	fbxwatchdog_unregister(wdt);

	priv = wdt->priv;
	clk_disable_unprepare(priv->clk);

	return 0;
}

static const struct of_device_id orion_fbxwdt_match_table[] = {
	{ .compatible = "marvell,orion-fbxwdt" },
	{},
};

struct platform_driver fbxwatchdog_platform_driver = {
	.probe	= fbxwatchdog_platform_probe,
	.remove	= fbxwatchdog_platform_remove,
	.driver	= {
		.name	= "orion_fbxwdt",
		.of_match_table = orion_fbxwdt_match_table,
	}
};

static int __init fbxwatchdog_orion_init(void)
{
	platform_driver_register(&fbxwatchdog_platform_driver);
	return 0;
}

static void __exit fbxwatchdog_orion_exit(void)
{
	platform_driver_unregister(&fbxwatchdog_platform_driver);
}

module_init(fbxwatchdog_orion_init);
module_exit(fbxwatchdog_orion_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nicolas Schichan <nschichan@freebox.fr>");
MODULE_DESCRIPTION("Freebox Watchdog, orion specific bits");

