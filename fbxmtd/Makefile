
# core support
obj-$(CONFIG_FREEBOX_MTD) += fbxmtd.o

fbxmtd-objs += fbxmtd_core.o fbxmtd_core_io.o
ifeq ($(CONFIG_FREEBOX_MTD_BACKEND_AMD),y)
fbxmtd-objs += fbxmtd_core_amd.o
endif

ifeq ($(CONFIG_FREEBOX_MTD_BACKEND_INTEL),y)
fbxmtd-objs += fbxmtd_core_intel.o
endif

# generic character device access support (r/w with read erase modify write)
obj-$(CONFIG_FREEBOX_MTD_CHAR) += fbxmtd_char.o
fbxmtd_char-objs += fbxmtd_char_dev.o

# generic r/o block device access support
obj-$(CONFIG_FREEBOX_MTD_BLK) += fbxmtd_blk.o
fbxmtd_blk-objs += fbxmtd_blk_dev.o

obj-$(CONFIG_FREEBOX_MTD_MAP_DRV_FBX) += fbxmtd_map_drv_fbx.o
obj-$(CONFIG_FREEBOX_MTD_MAP_DRV_BCM963XX) += fbxmtd_map_drv_bcm963xx.o
obj-$(CONFIG_FREEBOX_MTD_MAP_IOCTL) += fbxmtd_map_ioctl.o
