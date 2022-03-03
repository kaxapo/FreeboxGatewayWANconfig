obj-$(CONFIG_FBXATM) += fbxatm.o
obj-$(CONFIG_FBXATM_REMOTE) += fbxatm_remote.o

fbxatm-y := fbxatm_procfs.o fbxatm_sysfs.o

ifeq ($(CONFIG_FBXATM_STACK),y)
fbxatm-y += 	fbxatm_core.o	\
		fbxatm_2684.o	\
		fbxatm_dev.o	\
		crc10.o
fbxatm-$(CONFIG_PPP) += fbxatm_pppoa.o
endif

ifeq ($(CONFIG_FBXATM_REMOTE_STUB),y)
fbxatm-y += fbxatm_remote_stub.o
endif

obj-$(CONFIG_FBXATM_REMOTE_DRIVER) += fbxatm_remote_driver.o
