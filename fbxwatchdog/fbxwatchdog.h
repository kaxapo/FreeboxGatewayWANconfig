#ifndef FBXWATCHDOG_H
# define FBXWATCHDOG_H

struct fbxwatchdog {
	const char *name;
	void *priv;

	int enabled;
	int countdown;
	int countdown_min;

	int (*wdt_init)(struct fbxwatchdog *wdt);
	int (*wdt_cleanup)(struct fbxwatchdog *wdt);

	/*
	 * wdt_start and wdt_stop are called with wdt->lock held and irq
	 * disabled.
	 */
	int (*wdt_start)(struct fbxwatchdog *wdt);
	int (*wdt_stop)(struct fbxwatchdog *wdt);

	/*
	 * cb is called from interrupt/softirq context (depends on the
	 * underlying driver/hardware).
	 */
	void (*cb)(struct fbxwatchdog *wdt);

	struct timer_list timer;

	struct device *dev;

	/*
	 * protect interrupt handlers & start/stop methods running in
	 * thead context.
	 */
	spinlock_t	lock;
};

int fbxwatchdog_register(struct fbxwatchdog *wdt);
int fbxwatchdog_unregister(struct fbxwatchdog *wdt);

#ifdef CONFIG_FREEBOX_WATCHDOG_CHAR
int fbxwatchdog_char_add(struct fbxwatchdog *wdt);
void fbxwatchdog_char_remove(struct fbxwatchdog *wdt);
#endif

#endif /* !FBXWATCHDOG_H */
