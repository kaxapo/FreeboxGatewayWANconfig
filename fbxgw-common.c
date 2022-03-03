/*
 * fbxgw-common.c for fbxgw
 * Created by <nschichan@freebox.fr> on Wed Jan 21 16:10:06 2015
 */

#include <linux/kernel.h>
#include <linux/random.h>
#include <linux/netdevice.h>
#include <linux/gpio.h>
#include <linux/memblock.h>
#include <linux/pstore_ram.h>
#include <linux/platform_device.h>
#include <linux/mtd/physmap.h>
#include <linux/mtd/nand.h>
#include <linux/fbxatm_remote.h>

#include <asm/mach-types.h>
#include <asm/setup.h>

#include "mach/kirkwood_nand.h"

#include "fbxgw-switch.h"

#define PFX "fbxgw: "

/*
 * code that can be shared between fbxgw1r & fbxgw2r:
 * - crash zone init
 * - fbxserial stuff.
 * - nand timings & nand partitions
 * - ATAG_LOADER_VERSION and ATAG_BOOT_INFO entries in
 *   tagged list.
 */

/*
 * top of RAM - 32k, just below bootloader page table
 */
#define CRASH_ZONE_ADDR_FBXGW1R       0x1fff8000
#define CRASH_ZONE_ADDR_FBXGW2R       0x3fff8000

static phys_addr_t __init crash_zone_addr(void)
{
	if (machine_is_fbxgw1r())
		return CRASH_ZONE_ADDR_FBXGW1R;
	if (machine_is_fbxgw2r())
		return CRASH_ZONE_ADDR_FBXGW2R;

	return 0;
}

void __init fbxgw_reserve_crash_zone(void)
{
	phys_addr_t addr = crash_zone_addr();

	if (!addr) {
		pr_warn(PFX "invalid crash_zone_addr.\n");
		return ;
	}

	memblock_reserve(addr, SZ_16K);
}

static struct ramoops_platform_data ramoops_data = {
        .mem_size		= SZ_16K,
        .mem_address		= ~0 /* changed at runtime */,
        .record_size		= SZ_16K,
        .dump_oops		= 0,
        .ecc_info		= {
		.ecc_size = 16,
		.block_size = 0,
	},
};

static struct platform_device ramoops_dev = {
        .name = "ramoops",
        .dev = {
                .platform_data = &ramoops_data,
        },
};

static int __init fbxgw_setup_crash_zone(void)
{
	phys_addr_t addr = crash_zone_addr();

	if (!addr) {
		pr_warn(PFX "invalid crash_zone_addr.\n");
		return -EINVAL;
	}

	ramoops_data.mem_address = addr;
	return platform_device_register(&ramoops_dev);
}

arch_initcall(fbxgw_setup_crash_zone);

/*
 * NAND flash
 */
static struct mtd_partition fbxgw1r_nand_parts[] = {
	{
		.name = "all",
		.offset = 0,
		.size = MTDPART_SIZ_FULL,
		.mask_flags = MTD_WRITEABLE,
	}, {
		.name = "u-boot",
		.offset = 0,
		.size = SZ_1M,
		.mask_flags = MTD_WRITEABLE,
	}, {
		.name = "serial",
		.offset = SZ_1M,
		.size = SZ_1M,
		.mask_flags = MTD_WRITEABLE,
	}, {
		.name = "calibration",
		.offset = SZ_1M * 2,
		.size = SZ_1M,
		.mask_flags = MTD_WRITEABLE,
	}, {
		.name = "bank0",
		.offset = SZ_1M * 3,
		.size = SZ_1M * 18,
		.mask_flags = MTD_WRITEABLE,
	}, {
		.name = "nvram",
		.offset = SZ_1M * 21,
		.size = SZ_1M * 3,
	}, {
		.name = "bank1",
		.offset = SZ_1M * 24,
		.size = SZ_1M * 62,
	}, {
		.name = "femto",
		.offset = SZ_1M * 86,
		.size = SZ_1M * 16,
	}, {
		.name = "config",
		.offset = SZ_1M * 120,
		.size = SZ_1M * 8,
	}, {
		.name = "new_bank0",
		.offset = SZ_1M * 102,
		.size = SZ_1M * 18,
	},
};

/*
 * Hardcoded timings for two known NAND parts:
 * - NUMONYX NAND01GW3B2CZA6F
 * - TOSHIBA TC58NVG0S3EBAI4
 *
 * Kirkwood to ONFI mapping (from Marvell)
 * =======================================
 * TurnOff => tRHW
 * Acc2First => tCEA
 * Acc2Next => tRC
 * NFOEnW => tREH
 * CEn2WEn => tCS – tWP
 * WrLow => tWP
 * WrHigh => tWH
 *
 * = Numonyx
 * tRHW = 100ns | 20 Turnoff cycles (regvalue = 16)
 * tCEA = 25ns | 5 Acc2first cycles (regvalue = 9)
 * tRC = 25ns | 5 Acc2next cycles (regvalue = 5)
 * tREH = 10ns | 2 NOFEnW cycles (regvalue = 1)
 * tCS - tWP = 20ns - 12ns = 8ns | 2 CEn2WEn cycles (regvalue = 6)
 * tWp = 12ns | 3 WrLow cycles (regvalue = 3)
 * tWh = 10ns | 2 WrHigh cycles (regvalue = 2)
 * command delay: 25ns
 *
 * = Toshiba
 * tRHW = 30ns | 6 Turnoff cycles (regvalue 2)
 * tCEA = 25ns | 5 Acc2first cycles (regvalue 9)
 * tRC = 25ns | 5 Acc2next cycles (regvalue 5)
 * tREH = 10ns | 5 NOFEnW cycles (regvalue 2)
 * tCS - tWP = 20ns - 12ns = 8ns | 2 CEn2WEn cycles (regvalue = 6)
 * tWp = 12ns | 3 WrLow cycles (regvalue = 3)
 * tWh = 10ns | 2 WrHigh cycles (regvalue = 2)
 * command delay: 30ns
 *
 * all values are the same besides Turnoff
 * add one cycle for all values
 *
 * BEWARE: Acc2next & NFOEnW ARE LINKED ! Any additional cycles given
 * to NOFEnW must be accounted for in Acc2next
 */
#define NAND_COMMAND_DELAY	35

static void __init set_nand_timings(void)
{
	u32 val;
	u32 turnoff, acc2first, acc2next, nofenw, cen2wen, wrlow, wrhigh;
	void __iomem *nand_regs;

#ifdef CONFIG_FBXGW_COMMON_NAND_SAFE_READ_TIMINGS
	turnoff = 0x1f;
	acc2first = 0x1f;
	acc2next = 0x1f;
	nofenw = 0xc;
#else
	turnoff = 0x11;
	acc2first = 0xa;
	acc2next = 0x7;
	nofenw = 0x2;
#endif

#ifdef CONFIG_FBXGW_COMMON_NAND_SAFE_WRITE_TIMINGS
	cen2wen = 0xf;
	wrlow = 0xf;
	wrhigh = 0xf;
#else
	cen2wen = 0x7;
	wrlow = 0x4;
	wrhigh = 0x3;
#endif

	nand_regs = ioremap(NAND_PHYS_BASE, 0x100);
	if (!nand_regs) {
		/*
		 * FIXME: does this warrant a panic() ?
		 */
		pr_crit("unable to remap NAND registers to configure "
			"timings.\n");
		return ;
	}


	val = readl(nand_regs + NAND_RD_PARAM_OFF);
	/* turnoff */
	val &= ~(0x1f << 0);
	val |= (turnoff << 0);
	/* acc2first */
	val &= ~(0x1f << 6);
	val |= (acc2first << 6);
	/* acc2next */
	val &= ~(0x1f << 17);
	val |= (acc2next << 17);
	writel(val, nand_regs + NAND_RD_PARAM_OFF);

	val = readl(nand_regs + NAND_FLASH_CTL_OFF);
	/* nfoenw */
	val &= ~(0x1f << 9);
	val |= (nofenw << 9);
	writel(val, nand_regs + NAND_FLASH_CTL_OFF);

	val = readl(nand_regs + NAND_WR_PARAM_OFF);
	/* CEn2WEn */
	val &= ~(0xf << 0);
	val |= (cen2wen << 0);
	/* WrLow */
	val &= ~(0xf << 8);
	val |= (wrlow << 8);
	/* WrHigh */
	val &= ~(0xf << 16);
	val |= (wrhigh << 16);
	writel(val, nand_regs + NAND_WR_PARAM_OFF);

	iounmap(nand_regs);
}

#ifdef CONFIG_FBXGW_COMMON_PARTS_WRITE_ALL
static void __init set_parts_writeable(struct mtd_partition *parts, int count)
{
	int i;

	for (i = 0; i < count; ++i) {
		parts[i].mask_flags &= ~MTD_WRITEABLE;
	}
}
#endif


void __init fbxgw_common_nand_init(void)
{
	struct kirkwood_nand_ecc ecc;

	set_nand_timings();
#ifdef CONFIG_FBXGW_COMMON_PARTS_WRITE_ALL
	set_parts_writeable(fbxgw1r_nand_parts, ARRAY_SIZE(fbxgw1r_nand_parts));
#endif

	if (machine_is_fbxgw1r())
		ecc.ecc = NAND_ECC_SOFT;

	if (machine_is_fbxgw2r()) {
		ecc.ecc = NAND_ECC_SOFT_BCH;
		/* default to 4 bits error correction per 512 bytes for now */
		ecc.bch_ecc_size = 512;
		ecc.bch_ecc_bytes = 7;
	}

	kirkwood_nand_init_ecc(fbxgw1r_nand_parts,
			       ARRAY_SIZE(fbxgw1r_nand_parts),
			       NAND_COMMAND_DELAY, &ecc);
}

/*
 * fbxhwinfo fields, retrieved from ATAG list.
 */
char loader_version_str[128];
int loader_erase_nvram = 0;
int loader_bank0_forced = 0;
EXPORT_SYMBOL(loader_version_str);
EXPORT_SYMBOL(loader_erase_nvram);
EXPORT_SYMBOL(loader_bank0_forced);

static int parse_tag_loader_version(const struct tag *tag)
{
	const char *version;

	version = tag->u.loader_version.version;
	if (strncmp(version, "u-boot-", 7) ||
	    strlen(version) > sizeof (loader_version_str) - 1) {
		pr_info(PFX "invalid loader version.\n");
		return 0;
	}

	strcpy(loader_version_str, version);
	pr_info(PFX "loader version is '%s'\n", loader_version_str);
	return 0;
}
__tagtable(ATAG_LOADER_VERSION, parse_tag_loader_version);

static int __init fbxgw_parse_boot_info(const struct tag *tag)
{
	if (tag->u.boot_info.erase_nvram) {
		printk(KERN_INFO PFX "loader asked for nvram erase.\n");
		loader_erase_nvram = 1;
	}
	if (tag->u.boot_info.bank0_forced) {
		printk(KERN_INFO PFX "loader user forced a bank0 boot.\n");
		loader_bank0_forced = 1;
	}
	return 0;
}
__tagtable(ATAG_BOOT_INFO, fbxgw_parse_boot_info);

/*
 * fbxserialinfo stuff.
 */
struct fbx_serial serial;
static int got_serial;

const struct fbx_serial *arch_get_fbxserial(void)
{
	if (got_serial)
		 return &serial;
	return NULL;
}
EXPORT_SYMBOL(arch_get_fbxserial);

static int __init parse_fbxserial_tag(const struct tag *tag)
{
	memcpy(&serial, &tag->u.fbxserial, sizeof (serial));
	add_device_randomness(&serial, sizeof (serial));
	got_serial = 1;
	return 0;
}
__tagtable(ATAG_FBXSERIAL, parse_fbxserial_tag);

/*
 * board name for fbxhwinfo
 */
char fbxhwinfo_model[32];
EXPORT_SYMBOL(fbxhwinfo_model);
static int __init fbxgw_setup_model(void)
{
	if (machine_is_fbxgw1r())
		sprintf(fbxhwinfo_model, "fbxgw1r");
	if (machine_is_fbxgw2r())
		sprintf(fbxhwinfo_model, "fbxgw2r");
	return 0;
}
arch_initcall(fbxgw_setup_model);

void fbxgw_common_switch_init(struct net_device *dev,
			      int (*mii_read)(struct net_device *dev,
					      int phy_id, int reg),
			      void (*mii_write)(struct net_device *dev,
						int phy_id, int reg, int val))
{
	if (machine_is_fbxgw2r())
		marvell_6176_config(dev, 1, mii_read, mii_write);
	if (machine_is_fbxgw1r())
		marvell_6161_config(dev, 1, mii_read, mii_write);
}

void __init fbxgw_common_fixup_i2c(int bus_nr)
{
	int gpio_scl, gpio_sda;

	if (bus_nr == 0) {
		/*
		 * BUS0: use MPP 8 and 9
		 */
		gpio_sda = 8;
		gpio_scl = 9;
	} else if (bus_nr == 1) {
		/*
		 * BUS1: use MPP 36 and 37
		 */
		gpio_sda = 36;
		gpio_scl = 37;
	} else
		return;

	/*
	 * gpio_request will invoke pinctrl to put the MPPs in the
	 * correct function.
	 */

	gpio_request(gpio_sda, "sda");
	gpio_request(gpio_scl, "scl");
	gpio_direction_input(gpio_scl);
	gpio_direction_input(gpio_sda);

	if (!gpio_get_value(gpio_sda)) {
		size_t i;

		for (i = 0; i < 32; i++) {
			gpio_direction_output(gpio_scl, 0);
			udelay(100);
			gpio_direction_input(gpio_scl);
			udelay(100);
		}

		if (!gpio_get_value(gpio_sda))
			printk(KERN_ERR "i2c%d seems locked\n", bus_nr);
		else
			printk(KERN_ERR "i2c%d unlocked manually\n", bus_nr);
	}

	gpio_free(gpio_sda);
	gpio_free(gpio_scl);
}

/*
 * broadcom 6358 remote atm device
 */
static struct fbxatm_remote_pdata bcm6358_remote_pdata = {
	.remote_mac	= "\x00\x07\xcb\x00\x00\xfe",
	.netdev_name	= "eth0.43",
	.remote_name	= "bcm63xx_fbxxtm0",
};

static struct platform_device fbxatm_remote_device = {
	.name	= "fbxatm_remote",
	.id	= -1,
	.dev	= {
		.platform_data = &bcm6358_remote_pdata,
	},
};

void __init fbxgw_fbxatm_init(void)
{
	platform_device_register(&fbxatm_remote_device);
}
