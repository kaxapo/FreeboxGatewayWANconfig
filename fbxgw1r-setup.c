/*
 * Freebox GW01r
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2.  This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <linux/kernel.h>
#include <linux/gpio.h>
#include <linux/delay.h>
#include <linux/platform_device.h>
#include <linux/fbxgpio_core.h>
#include <linux/smsc_cap1066.h>
#include <linux/platform_data/at24.h>
#include <linux/i2c.h>
#include <linux/input.h>
#include <linux/spi/spi.h>
#include <linux/spi/flash.h>
#include <linux/spi/ssd1327.h>

#include <mach/board_fbxgw1r.h>

#define PFX	"fbxgw1r: "

#include "fbxgw-switch.h"
#include "fbxgw-common.h"
#include "fbxgw-pcie.h"

/*
 * set shift registers output to given value
 */
static void set_shift_register(u8 val)
{
	int i;

	gpio_set_value(GPIO_SR_CLK, 0);
	gpio_set_value(GPIO_SR_LOAD, 0);

	udelay(1);

	for (i = 7; i >= 0; i--) {
		gpio_set_value(GPIO_SR_DIN, (val & (1 << i)) ? 1 : 0);
		udelay(100);
		gpio_set_value(GPIO_SR_CLK, 1);
		udelay(100);
		gpio_set_value(GPIO_SR_CLK, 0);
	}

	udelay(1);
	gpio_set_value(GPIO_SR_LOAD, 1);
	udelay(1);
}

/*
 * reset values can not be read back from shift registers, we have to
 * keep them
 */
static DEFINE_SPINLOCK(sr_lock);
static unsigned long sr_value;

/*
 * clear or set sr bit
 */
static void sr_set_bit(int bit, int value)
{
	unsigned long flags;

	value = !!value;
	spin_lock_irqsave(&sr_lock, flags);
	sr_value &= ~(1 << bit);
	sr_value |= (value << bit);
	set_shift_register((u8)sr_value);
	spin_unlock_irqrestore(&sr_lock, flags);
}

/*
 * return cached bit value
 */
static int sr_get_bit(int bit)
{
	return test_bit(bit, &sr_value);
}

/*
 * control PCIe bus reset
 */
static void fbxgw1r_pcie_reset(int value)
{
	sr_set_bit(SROUT_PCIE_RST, value);
}

/*
 * control marvell swith reset
 */
static void fbxgw1r_marvell_switch_reset(int value)
{
	gpio_set_value(GPIO_SW_RESET, value);
}

static int fbxgw1r_do_vlan(void)
{
	return 1;
}

#define NFS_VLAN_ID 41

int marvell_6161_config(struct net_device *dev, int probe,
			int (*mii_read)(struct net_device *dev,
					int phy_id, int reg),
			void (*mii_write)(struct net_device *dev,
					  int phy_id, int reg, int val))
{
	u16 val;
	struct mii_struct mii = {
		.dev = dev,
		.read = mii_read,
		.write = mii_write,
	};

	if (!probe)
		return 0;

	/* switch needs more than 1 second (!) to go out of reset */
	fbxgw1r_marvell_switch_reset(0);
	mdelay(1);
	fbxgw1r_marvell_switch_reset(1);
	msleep(2000);

	/* probe */
	val = mii.read(mii.dev, SWPORT(0), PORTREG_SWITCH_IDENTIFIER);
	if (PRODUCT_NUM(val) != 0x161) {
		printk(KERN_ERR PFX "unknown switch id: 0x%08x\n",
		       PRODUCT_NUM(val));
		return 1;
	}
	mii.dev_id = PRODUCT_NUM(val);
	mii.indirect_phy_access = false;

	fbxgw_sw_config_cpu_port(&mii, SWPORT(5));
	fbxgw_sw_config_phy_port(&mii, PHYPORT(1));


	if (fbxgw1r_do_vlan()) {
		const u8 config[6] = {
			PDATA_NOT_MEMBER,
			PDATA_MEMBER_UNTAGGED,
			PDATA_NOT_MEMBER,
			PDATA_NOT_MEMBER,
			PDATA_NOT_MEMBER,
			PDATA_MEMBER_TAGGED,
		};

		fbxgw_sw_vtu_load(&mii, NFS_VLAN_ID, config, sizeof (config));

		fbxgw_sw_port_default_vid(&mii, SWPORT(1), NFS_VLAN_ID);
		fbxgw_sw_port_dot1q_secure(&mii, SWPORT(1));
		fbxgw_sw_port_dot1q_secure(&mii, SWPORT(5));
	}

	fbxgw_sw_port_forward_enable(&mii, SWPORT(1));
	fbxgw_sw_port_forward_enable(&mii, SWPORT(5));

	printk(KERN_INFO PFX "marvell 6161 initialized\n");
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
		.max_speed_hz	= 4 * 1000 * 1000,
		.bus_num	= 0,
		.chip_select    = 1,
	},
};

/*
 * fbxgpio
 */
static struct fbxgpio_operations fbxgw1r_gpio_ops = {
	/* cast only for signed/unsigned */
	.get_datain = (int (*)(int))gpio_get_value,
	.get_dataout = (int (*)(int))gpio_get_value,
	.set_dataout = (void (*)(int, int))gpio_set_value,
};

static struct fbxgpio_operations fbxgw1r_sr_ops = {
	.get_dataout = sr_get_bit,
	.set_dataout = sr_set_bit,
};

static struct fbxgpio_pin fbxgw1r_gpio_pins[] = {
	/* marvell gpios */
	{
		.pin_name	 = "oled-data-select",
		.direction	= GPIO_DIR_OUT,
		.pin_num	= GPIO_OLED_DATA_SELECT,
		.ops		= &fbxgw1r_gpio_ops,
	},
	{
		.pin_name	= "test-mode",
		.direction	= GPIO_DIR_IN,
		.pin_num	= GPIO_TEST_MODE,
		.ops		= &fbxgw1r_gpio_ops,
	},
	{
		.pin_name	= "sfp-txdis",
		.direction	= GPIO_DIR_OUT,
		.pin_num	= GPIO_SFP_TXDIS,
		.ops		= &fbxgw1r_gpio_ops,
	},
	{
		.pin_name	= "sw-reset",
		.direction	= GPIO_DIR_OUT,
		.pin_num	= GPIO_SW_RESET,
		.ops		= &fbxgw1r_gpio_ops,
	},
	{
		.pin_name	= "sw-int",
		.direction	= GPIO_DIR_IN,
		.pin_num	= GPIO_SW_INT,
		.ops		= &fbxgw1r_gpio_ops,
	},
	{
		.pin_name	= "sfp-pwrgood",
		.direction	= GPIO_DIR_IN,
		.pin_num	= GPIO_SFP_PWRGOOD,
		.ops		= &fbxgw1r_gpio_ops,
	},
	{
		.pin_name	= "sfp-txfault",
		.direction	= GPIO_DIR_IN,
		.pin_num	= GPIO_SFP_TXFAULT,
		.ops		= &fbxgw1r_gpio_ops,
	},
	{
		.pin_name	= "sfp-presence",
		.direction	= GPIO_DIR_IN,
		.pin_num	= GPIO_SFP_PRESENCE,
		.ops		= &fbxgw1r_gpio_ops,
	},
	{
		.pin_name	= "sfp-rxloss",
		.direction	= GPIO_DIR_IN,
		.pin_num	= GPIO_SFP_RXLOSS,
		.ops		= &fbxgw1r_gpio_ops,
	},
	{
		.pin_name	= "exp-rst",
		.direction	= GPIO_DIR_OUT,
		.pin_num	= GPIO_EXP_RST,
		.ops		= &fbxgw1r_gpio_ops,
	},
	{
		.pin_name	= "pos-sense",
		.direction	= GPIO_DIR_IN,
		.pin_num	= GPIO_POS_SENSE,
		.ops		= &fbxgw1r_gpio_ops,
	},
	{
		.pin_name	= "exp-pwrgood",
		.direction	= GPIO_DIR_IN,
		.pin_num	= GPIO_EXP_PWRGOOD,
		.ops		= &fbxgw1r_gpio_ops,
	},
	{
		.pin_name	= "exp-presence",
		.direction	= GPIO_DIR_IN,
		.pin_num	= GPIO_EXP_PRESENCE,
		.ops		= &fbxgw1r_gpio_ops,
	},
	{
		.pin_name	= "kp-int",
		.direction	= GPIO_DIR_IN,
		.pin_num	= GPIO_KP_INT,
		.ops		= &fbxgw1r_gpio_ops,
	},
	{
		.pin_name	= "board-id-0",
		.direction	= GPIO_DIR_IN,
		.pin_num	= GPIO_BOARD_ID_0,
		.ops		= &fbxgw1r_gpio_ops,
	},
	{
		.pin_name	= "board-id-1",
		.direction	= GPIO_DIR_IN,
		.pin_num	= GPIO_BOARD_ID_1,
		.ops		= &fbxgw1r_gpio_ops,
	},

	/* shift registers resets */
	{
		.pin_name       = "sfp-pwren",
		.direction      = GPIO_DIR_OUT,
		.pin_num	= SROUT_SFP_PWREN,
		.ops		= &fbxgw1r_sr_ops,
	},
	{
		.pin_name       = "usb-rst",
		.direction      = GPIO_DIR_OUT,
		.pin_num	= SROUT_USB_RST,
		.ops		= &fbxgw1r_sr_ops,
	},
	{
		.pin_name       = "audio-rst",
		.direction      = GPIO_DIR_OUT,
		.pin_num	= SROUT_AUDIO_RST,
		.ops		= &fbxgw1r_sr_ops,
	},
	{
		.pin_name       = "exp-pwren",
		.direction      = GPIO_DIR_OUT,
		.pin_num	= SROUT_EXP_PWREN,
		.ops		= &fbxgw1r_sr_ops,
	},
	{
		.pin_name       = "bcm-rst",
		.direction      = GPIO_DIR_OUT,
		.pin_num	= SROUT_BCM_RST,
		.ops		= &fbxgw1r_sr_ops,
	},
	{
		.pin_name       = "pcie-rst",
		.direction      = GPIO_DIR_OUT,
		.pin_num	= SROUT_PCIE_RST,
		.ops		= &fbxgw1r_sr_ops,
	},
	{
		.pin_name       = "keypad-oled-rst",
		.direction      = GPIO_DIR_OUT,
		.pin_num	= SROUT_KEYPAD_OLED_RST,
		.ops		= &fbxgw1r_sr_ops,
	},
	{
		.pin_name       = "keypad-pwren",
		.direction      = GPIO_DIR_OUT,
		.pin_num	= SROUT_OLED_PWREN,
		.ops		= &fbxgw1r_sr_ops,
	},


	{  },
};

static struct platform_device fbxgw1r_gpio_device = {
	.name   = "fbxgpio",
	.id     = -1,
	.dev    = {
		.platform_data = &fbxgw1r_gpio_pins,
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

static struct i2c_board_info fbxgw1r_i2c_devs[] = {
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

void __init fbxgw1r_init(void)
{
	struct fbxgw_pcie_priv *pex_priv;

	printk("fbxgw1r-init.\n");
	panic_timeout = 10;
	panic_on_oops = 1;

	fbxgw_common_fixup_i2c(0);

	gpio_request(GPIO_OLED_DATA_SELECT, "oled-data-select");
	gpio_request(GPIO_SR_CLK, "sr-clk");
	gpio_request(GPIO_SR_DIN, "sr-din");
	gpio_request(GPIO_TEST_MODE, "test-mode");
	gpio_request(GPIO_SFP_TXDIS, "sfp-txdis");
	gpio_request(GPIO_SR_LOAD, "sr-load");
	gpio_request(GPIO_SW_RESET, "sw-reset");
	gpio_request(GPIO_SW_INT, "sw-int");
	gpio_request(GPIO_SFP_PWRGOOD, "sfp-pwrgood");
	gpio_request(GPIO_SFP_TXFAULT, "sfp-txfault");
	gpio_request(GPIO_SPI_CS_BCM, "spi-cs-bcm");
	gpio_request(GPIO_SFP_PRESENCE, "sfp-presence");
	gpio_request(GPIO_SFP_RXLOSS, "sfp-rxloss");
	gpio_request(GPIO_EXP_RST, "exp-rst");
	gpio_request(GPIO_POS_SENSE, "pos-sense");
	gpio_request(GPIO_EXP_PWRGOOD, "exp-pwrgood");
	gpio_request(GPIO_EXP_PRESENCE, "exp-presence");
	gpio_request(GPIO_KP_INT, "kp-int");
	gpio_request(GPIO_BOARD_ID_0, "board-id-0");
	gpio_request(GPIO_BOARD_ID_1, "board-id-1");

	gpio_direction_output(GPIO_OLED_DATA_SELECT, 0);
	gpio_direction_output(GPIO_SR_CLK, 0);
	gpio_direction_output(GPIO_SR_DIN, 0);
	gpio_direction_input(GPIO_TEST_MODE);
	gpio_direction_output(GPIO_SFP_TXDIS, 1);
	gpio_direction_output(GPIO_SR_LOAD, 0);
	gpio_direction_output(GPIO_SW_RESET, 1);
	gpio_direction_input(GPIO_SW_INT);
	gpio_direction_input(GPIO_SFP_PWRGOOD);
	gpio_direction_input(GPIO_SFP_TXFAULT);
	gpio_direction_output(GPIO_SPI_CS_BCM, 1);
	gpio_direction_input(GPIO_SFP_PRESENCE);
	gpio_direction_input(GPIO_SFP_RXLOSS);
	gpio_direction_output(GPIO_EXP_RST, 0);
	gpio_direction_input(GPIO_POS_SENSE);
	gpio_direction_input(GPIO_EXP_PWRGOOD);
	gpio_direction_input(GPIO_EXP_PRESENCE);
	gpio_direction_input(GPIO_KP_INT);
	gpio_direction_input(GPIO_BOARD_ID_0);
	gpio_direction_input(GPIO_BOARD_ID_1);

	/* set shift register default value */
	sr_value = (0 << SROUT_PCIE_RST) |
		(0 << SROUT_BCM_RST) |
		(1 << SROUT_KEYPAD_OLED_RST) |
		(0 << SROUT_SFP_PWREN) |
		(1 << SROUT_USB_RST) |
		(1 << SROUT_AUDIO_RST) |
		(0 << SROUT_EXP_PWREN) |
		(1 << SROUT_OLED_PWREN);
	set_shift_register((u8)sr_value);

	i2c_register_board_info(0, fbxgw1r_i2c_devs,
				ARRAY_SIZE(fbxgw1r_i2c_devs));
	spi_register_board_info(spi_board_info, ARRAY_SIZE(spi_board_info));
	fbxgw_common_nand_init();

	if (fbxgw_pcie_preinit(&pex_priv) == 0) {
		fbxgw1r_pcie_reset(0);
		mdelay(100);
		fbxgw1r_pcie_reset(1);
		mdelay(100);
		fbxgw_pcie_retrain_link(pex_priv);
		fbxgw_pcie_preexit(pex_priv);
	}

	fbxgw_fbxatm_init();
	platform_device_register(&fbxgw1r_gpio_device);
}
