/*
 * fbxgw2r-setup.c for fbxgw2r
 * Created by <nschichan@freebox.fr> on Thu Jan 22 14:27:03 2015
 */

#include <linux/kernel.h>
#include <linux/gpio.h>
#include <linux/fbxgpio_core.h>
#include <linux/platform_device.h>
#include <linux/delay.h>
#include <linux/i2c.h>
#include <linux/platform_data/at24.h>
#include <linux/smsc_cap1066.h>
#include <linux/input.h>
#include <linux/spi/spi.h>
#include <linux/spi/flash.h>
#include <linux/spi/ssd1327.h>

#include <mach/board_fbxgw2r.h>

#include "fbxgw.h"
#include "fbxgw-common.h"
#include "fbxgw-switch.h"
#include "fbxgw-pcie.h"

#define PFX	"fbxgw2r: "

/*
 * reset whatever is behind the (inactive) mini-PCIe connector
 */
static void fbxgw2r_pcie_reset(int value)
{
	gpio_set_value(GPIO_PCIE_RST, value);
}

/*
 * reset onboard WLAN chip.
 */
static void fbxgw2r_wlan_rst(int value)
{
	gpio_set_value(GPIO_WLAN_RST, value);
}

/*
 * reset onboard audio codec
 */
static void fbxgw2r_audio_rst(int value)
{
	gpio_set_value(GPIO_AUDIO_RST, value);
}

static void fbxgw2r_marvell_switch_reset(int value)
{
	gpio_set_value(GPIO_SW_RESET, value);
}

static int fbxgw2r_do_vlan(void)
{
	/* hardcode to 1 for now. */
	return 1;
}

#define NFS_VLAN_ID			41

int marvell_6176_config(struct net_device *dev, int probe,
			int (*mii_read)(struct net_device *dev,
					int phy_id, int reg),
			void (*mii_write)(struct net_device *dev,
					  int phy_id, int reg, int val))
{
	u16 val;
	struct mii_struct mii = {
		.dev_id = 0,
		.dev = dev,
		.read = mii_read,
		.write = mii_write,
	};

	if (!probe)
		return 0;

	fbxgw2r_marvell_switch_reset(0);
	msleep(1);
	fbxgw2r_marvell_switch_reset(1);
	msleep(2000);

	/* probe */
	val = mii_read(dev, SWPORT(0), PORTREG_SWITCH_IDENTIFIER);
	if (PRODUCT_NUM(val) != 0x176) {
		printk(KERN_ERR PFX "unknown switch id: 0x%08x\n",
		       PRODUCT_NUM(val));
		return 1;
	}
	mii.dev_id = PRODUCT_NUM(val);
	mii.indirect_phy_access = true;

	fbxgw_sw_config_cpu_port(&mii, SWPORT(5));
	fbxgw_sw_config_phy_port(&mii, PHYPORT(0));

	mii.write(dev, SWPORT(0), 0x16, 0x8011);
	mii.write(dev, SWPORT(1), 0x16, 0x8011);
	mii.write(dev, SWPORT(2), 0x16, 0x8011);
	mii.write(dev, SWPORT(3), 0x16, 0x8011);

	if (fbxgw2r_do_vlan()) {
		const u8 config[7] = {
			PDATA_MEMBER_UNTAGGED,
			PDATA_NOT_MEMBER,
			PDATA_NOT_MEMBER,
			PDATA_NOT_MEMBER,
			PDATA_NOT_MEMBER,
			PDATA_MEMBER_TAGGED,
			PDATA_NOT_MEMBER,
		};

		fbxgw_sw_vtu_stu_init(&mii, PCR_PORTSTATE_FORWARDING,
				      sizeof (config));
		fbxgw_sw_vtu_load(&mii, NFS_VLAN_ID, config, sizeof (config));

		fbxgw_sw_port_default_vid(&mii, SWPORT(0), NFS_VLAN_ID);
		fbxgw_sw_port_dot1q_secure(&mii, SWPORT(0));
		fbxgw_sw_port_dot1q_secure(&mii, SWPORT(5));
	}

	fbxgw_sw_port_forward_enable(&mii, SWPORT(5));
	fbxgw_sw_port_forward_enable(&mii, SWPORT(0));

	printk(KERN_INFO PFX "marvell 6176 initialized\n");

	return 0;
}

static const struct flash_platform_data	flash_info = {
	.name		= "bcmflash",
};

static const struct ssd1327_platform_data ssd1327_pd = {
	.data_select_gpio	= GPIO_OLED_DATA_SELECT,
	.width			= 128,
	.height			= 128,
	.rotate			= 270,
	.watchdog		= 300,
};

static struct spi_board_info spi_board_info[] __initdata = {
	{
		.modalias       = "ssd1327",
		.platform_data	= &ssd1327_pd,
		.mode		= SPI_MODE_0,
		.max_speed_hz	= 10 * 1000 * 1000,
		.bus_num	= 0,
		.chip_select    = 0,
	},
	{
		.modalias       = "m25p80",
		.platform_data	= &flash_info,
		.mode		= SPI_MODE_0,
		.max_speed_hz	= 1 * 1000 * 1000,
		.bus_num	= 0,
		.chip_select    = 1,
	},
};

/*
 * fbxgpio
 */
static struct fbxgpio_operations fbxgw2r_gpio_ops = {
	/* cast only for signed/unsigned */
	.get_datain = (int (*)(int))gpio_get_value,
	.get_dataout = (int (*)(int))gpio_get_value,
	.set_dataout = (void (*)(int, int))gpio_set_value,
};

static struct fbxgpio_pin fbxgw2r_gpio_pins[] = {
	/* marvell gpios */
	{
		.pin_name	= "bcm-rst",
		.direction	= GPIO_DIR_OUT,
		.pin_num	= GPIO_BCM_RST,
		.ops		= &fbxgw2r_gpio_ops,
	},
	{
		.pin_name	= "pcie-rst",
		.direction	= GPIO_DIR_OUT,
		.pin_num	= GPIO_PCIE_RST,
		.ops		= &fbxgw2r_gpio_ops,
	},
	{
		.pin_name	= "sw-int",
		.direction	= GPIO_DIR_IN,
		.pin_num	= GPIO_SW_INT,
		.ops		= &fbxgw2r_gpio_ops,
	},
	{
		.pin_name	= "test-mode",
		.direction	= GPIO_DIR_IN,
		.pin_num	= GPIO_TEST_MODE,
		.ops		= &fbxgw2r_gpio_ops,
	},
	{
		.pin_name	= "sfp-pwren",
		.direction	= GPIO_DIR_OUT,
		.pin_num	= GPIO_SFP_PWREN,
		.ops		= &fbxgw2r_gpio_ops,
	},
	{
		.pin_name	= "sfp-txdis",
		.direction	= GPIO_DIR_OUT,
		.pin_num	= GPIO_SFP_TXDIS,
		.ops		= &fbxgw2r_gpio_ops,
	},
	{
		.pin_name	= "sfp-pwrgood",
		.direction	= GPIO_DIR_IN,
		.pin_num	= GPIO_SFP_PWRGOOD,
		.ops		= &fbxgw2r_gpio_ops,
	},
	{
		.pin_name	= "sfp-presence",
		.direction	= GPIO_DIR_IN,
		.pin_num	= GPIO_SFP_PRESENCE,
		.ops		= &fbxgw2r_gpio_ops,
	},
	{
		.pin_name	= "sfp-rxloss",
		.direction	= GPIO_DIR_IN,
		.pin_num	= GPIO_SFP_RXLOSS,
		.ops		= &fbxgw2r_gpio_ops,
	},
	{
		.pin_name	= "sfp-txfault",
		.direction	= GPIO_DIR_IN,
		.pin_num	= GPIO_SFP_TXFAULT,
		.ops		= &fbxgw2r_gpio_ops,
	},
	{
		.pin_name	= "audio-rst",
		.direction	= GPIO_DIR_OUT,
		.pin_num	= GPIO_AUDIO_RST,
		.ops		= &fbxgw2r_gpio_ops,
	},
	{
		.pin_name	= "pos-sense",
		.direction	= GPIO_DIR_IN,
		.pin_num	= GPIO_POS_SENSE,
		.ops		= &fbxgw2r_gpio_ops,
	},
	{
		.pin_name	= "exp-presence",
		.direction	= GPIO_DIR_IN,
		.pin_num	= GPIO_EXP_PRESENCE,
		.ops		= &fbxgw2r_gpio_ops,
	},
	{
		.pin_name	= "exp-pwrgood",
		.direction	= GPIO_DIR_IN,
		.pin_num	= GPIO_EXP_PWRGOOD,
		.ops		= &fbxgw2r_gpio_ops,
	},
	{
		.pin_name	= "exp-pwren",
		.direction	= GPIO_DIR_OUT,
		.pin_num	= GPIO_EXP_PWREN,
		.ops		= &fbxgw2r_gpio_ops,
	},
	{
		.pin_name	= "exp-rst",
		.direction	= GPIO_DIR_OUT,
		.pin_num	= GPIO_EXP_RST,
		.ops		= &fbxgw2r_gpio_ops,
	},
	{
		.pin_name	= "sw-reset",
		.direction	= GPIO_DIR_OUT,
		.pin_num	= GPIO_SW_RESET,
		.ops		= &fbxgw2r_gpio_ops,
	},

	{ },
};

static struct platform_device fbxgw2r_gpio_device = {
	.name   = "fbxgpio",
	.id     = -1,
	.dev    = {
		.platform_data = &fbxgw2r_gpio_pins,
	},
};

/*
 * i2c midplane eeprom.
 */
static struct at24_platform_data midplane_eeprom_data = {
	.byte_len	= 4096,
	.page_size	= 8,
	.flags		= AT24_FLAG_ADDR16,
};

/*
 * expansion board eeprom.
 */
static struct at24_platform_data expansion_eeprom_data = {
	.byte_len	= 32768,
	.page_size	= 64,
	.flags		= AT24_FLAG_ADDR16,
};

/*
 * i2c smsc
 */
static struct smsc_cap1066_pdata cap1066_pdata = {
	.key_map = {
		KEY_DOWN,
		KEY_LEFT,
		KEY_UP,
		0,
		KEY_ENTER,
		KEY_RIGHT,
	},

	.has_irq_gpio = true,
	.irq_gpio = GPIO_KP_INT,
};

static struct i2c_board_info fbxgw2r_i2c0_devs[] = {
	{
		.type		= "cap1066",
		.addr		= 0x28,
		.platform_data	= &cap1066_pdata,
	},
	{
		.type		= "24c32",
		.addr		= 0x57,
		.platform_data	= &midplane_eeprom_data,
	},
	{
		.type		= "24c256",
		.addr		= 0x53,
		.platform_data	= &expansion_eeprom_data,
	},
};

struct platform_device fbxgw2r_audio = {
	.name = "fbxgw2r-audio",
	.id = -1,
};

void __init fbxgw2r_init(void)
{
	extern int panic_timeout;
	struct fbxgw_pcie_priv *pex_priv;

	printk("fbxgw2r-init.\n");

	panic_timeout = 10;
	panic_on_oops = 1;

	fbxgw_common_fixup_i2c(0);
	fbxgw_common_fixup_i2c(1);

	gpio_request(GPIO_OLED_DATA_SELECT, "oled-data-select");
	gpio_request(GPIO_WLAN_RST, "wlan-rst");
	gpio_request(GPIO_PCIE_RST, "pcie-rst");
	gpio_request(GPIO_SW_RESET, "sw-reset");
	gpio_request(GPIO_SW_INT, "sw-int");
	gpio_request(GPIO_TEST_MODE, "test-mode");
	gpio_request(GPIO_SPI_CS_BCM, "spi-cs-bcm");
	gpio_request(GPIO_BCM_RST, "bcm-rst");
	gpio_request(GPIO_SFP_TXDIS, "sfp-txdis");
	gpio_request(GPIO_SFP_PRESENCE, "sfp-presence");
	gpio_request(GPIO_SFP_PWRGOOD, "sfp-pwrgood");
	gpio_request(GPIO_SFP_TXFAULT, "sfp-txfault");
	gpio_request(GPIO_SFP_RXLOSS, "sfp-rxloss");
	gpio_request(GPIO_KP_INT, "kp-int");
	gpio_request(GPIO_SFP_PWREN, "sfp-pwren");
	gpio_request(GPIO_POS_SENSE, "pos-sense");
	gpio_request(GPIO_AUDIO_RST, "audio-rst");

	gpio_request(GPIO_EXP_PWREN, "exp-pwren");
	gpio_request(GPIO_EXP_PWRGOOD, "exp-pwrgood");
	gpio_request(GPIO_EXP_PRESENCE, "exp-presence");
	gpio_request(GPIO_EXP_RST, "exp-rst");

	gpio_direction_output(GPIO_OLED_DATA_SELECT, 0);
	gpio_direction_output(GPIO_WLAN_RST, 0);
	gpio_direction_input(GPIO_TEST_MODE);
	gpio_direction_output(GPIO_PCIE_RST, 0);
	gpio_direction_output(GPIO_SW_RESET, 0);
	gpio_direction_input(GPIO_SW_INT);
	gpio_direction_output(GPIO_SPI_CS_BCM, 1);
	gpio_direction_output(GPIO_BCM_RST, 0);
	gpio_direction_output(GPIO_AUDIO_RST, 0);
	gpio_direction_input(GPIO_POS_SENSE);

	gpio_direction_output(GPIO_SFP_PWREN, 0);
	gpio_direction_output(GPIO_SFP_TXDIS, 1);
	gpio_direction_input(GPIO_SFP_PRESENCE);
	gpio_direction_input(GPIO_SFP_PWRGOOD);
	gpio_direction_input(GPIO_SFP_TXFAULT);
	gpio_direction_input(GPIO_SFP_RXLOSS);

	gpio_direction_output(GPIO_EXP_PWREN, 0);
	gpio_direction_output(GPIO_EXP_RST, 0);
	gpio_direction_input(GPIO_EXP_PRESENCE);
	gpio_direction_input(GPIO_EXP_PWRGOOD);

	i2c_register_board_info(0, fbxgw2r_i2c0_devs,
				ARRAY_SIZE(fbxgw2r_i2c0_devs));

	spi_register_board_info(spi_board_info, ARRAY_SIZE(spi_board_info));

	fbxgw_common_nand_init();

	if (fbxgw_pcie_preinit(&pex_priv) == 0) {
		fbxgw2r_pcie_reset(0);
		fbxgw2r_wlan_rst(0);
		mdelay(100);
		fbxgw2r_pcie_reset(1);
		fbxgw2r_wlan_rst(1);
		mdelay(100);
		fbxgw_pcie_retrain_link(pex_priv);
		fbxgw_pcie_preexit(pex_priv);
	}

	/* reset audio codec */
	fbxgw2r_audio_rst(0);
	mdelay(100);
	fbxgw2r_audio_rst(1);

	fbxgw_fbxatm_init();
	platform_device_register(&fbxgw2r_gpio_device);
	platform_device_register(&fbxgw2r_audio);
}
