obj-$(CONFIG_FREEBOX_WATCHDOG) += fbxwatchdog.o

fbxwatchdog-objs = fbxwatchdog_core.o
ifeq ($(CONFIG_FREEBOX_WATCHDOG_CHAR),y)
fbxwatchdog-objs += fbxwatchdog_char.o
endif

obj-$(CONFIG_FREEBOX_WATCHDOG_ORION)	+= fbxwatchdog_orion.o
obj-$(CONFIG_FREEBOX_WATCHDOG_BCM63XX)	+= fbxwatchdog_bcm63xx.o
