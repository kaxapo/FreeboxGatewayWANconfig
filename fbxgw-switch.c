/*
 * fbxgw-switch.c for fbxgw-switch
 * Created by <nschichan@freebox.fr> on Tue Jun  5 20:46:17 2012
 */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/delay.h>
#include <linux/errno.h>

#include "fbxgw-switch.h"

#define PFX "fbxgw-switch: "


#define MARVELL_PHYPORT0		0x00

#define MARVELL_SWPORT0			0x10
#define MARVELL_SWPORT4			0x14
#define MARVELL_SWPORT5			0x15

#define PORTREG_PCS			0x1

#define PCS_RGMII_RX_DELAY		(1 << 15)
#define PCS_RGMII_TX_DELAY		(1 << 14)
#define PCS_FORCELINK_UP		(1 << 5)
#define PCS_FORCELINK			(1 << 4)
#define PCS_FORCEDUPLEX_FULL		(1 << 3)
#define PCS_FORCEDUPLEX			(1 << 2)
#define PCS_FORCESPEED_10		0x0
#define PCS_FORCESPEED_100		0x1
#define PCS_FORCESPEED_1000		0x2
#define PCS_FORCESPEED_AUTO		0x3

#define PORTREG_PCR			0x4
#define PCR_PORTSTATE_DISABLED		0x0
/* #define PCR_PORTSTATE_FORWARDING	0x3 */

#define PORTREG_VLANID			0x7

#define PORTREG_PCR2			0x8
#define PCR2_MODE_SHIFT			10
#define PCR2_MODE_SECURE		3

#define MARVELL_GLOBAL1			0x1b
#define MARVELL_GLOBAL2			0x1c

#define GLOBREG_VTUFID			0x2
#define GLOBREG_VTUSID			0x3

#define GLOBREG_GCR			0x4
#define GCR_PPUEN			(1 << 14)

#define GLOBREG_VTUOP			0x5
#define VTUOP_BUSY			(1 << 15)
#define VTUOP_OP_LOAD			(0x3 << 12)
#define VTUOP_OP_STU_LOAD		(0x5 << 12)
#define VTUOP_OP_GETNEXT		(0x4 << 12)

#define GLOBREG_VTUVID			0x6
#define VTUVID_VALID			(1 << 12)

#define GLOBREG_VTU_P03_DATA		0x7
#define GLOBREG_VTU_P46_DATA		0x8

#define GLOBREG_VTU_DATA		0x9

#define GLOBREG_SMI_CMD			0x18
# define SMI_CMD_BUSY			(1 << 15)
# define SMI_CLAUSE_22			(1 << 12)
# define SMI_CMD_READ			(2 << 10)
# define SMI_CMD_WRITE			(1 << 10)
# define SMI_DEVADDR(DevAddr)	(DevAddr << 5)
# define SMI_REGADDR(RegAddr)	(RegAddr)
#define GLOBREG_SMI_DATA		0x19

#define GLOBREG_GSR			0x0
# define GSR_PPU_POLLING		(1 << 15)


/*
 * voodo register content. P4_RGMII_FORCE is effective on revision A2
 * of mv6161 chip. see revision A2 release notes for details.
 */
#define P4_RGMII_DELAY			0x03
#define P5_RGMII_DELAY			0x18



static int __mii_indirect_wait(struct mii_struct *mii, int tries)
{
	while (tries) {
		u16 val = mii->read(mii->dev, MARVELL_GLOBAL2, GLOBREG_SMI_CMD);
		if ((val & SMI_CMD_BUSY) == 0)
			return 0;
		udelay(1000);
		--tries;
	}
	return -ETIMEDOUT;
}

static int __mii_indirect_read(struct mii_struct *mii, int phy_id, int reg)
{
	u16 smi_cmd = SMI_CMD_BUSY | SMI_CLAUSE_22 | SMI_CMD_READ |
		SMI_DEVADDR(phy_id) | SMI_REGADDR(reg);

	mii->write(mii->dev, MARVELL_GLOBAL2, GLOBREG_SMI_CMD, smi_cmd);
	if (__mii_indirect_wait(mii, 1000) < 0) {
		printk(KERN_WARNING PFX "indirect phy read did not "
		       "complete.\n");
		return 0xffff;
	}
	return mii->read(mii->dev, MARVELL_GLOBAL2, GLOBREG_SMI_DATA);
}

static int mii_phy_read(struct mii_struct *mii, int phy_id, int reg)
{
	if (mii->indirect_phy_access == false)
		return mii->read(mii->dev, phy_id, reg);
	else
		return __mii_indirect_read(mii, phy_id, reg);
}

static void __mii_indirect_write(struct mii_struct *mii, int phy_id, int reg,
				int val)
{
	u16 smi_cmd = SMI_CMD_BUSY | SMI_CLAUSE_22 | SMI_CMD_WRITE |
		SMI_DEVADDR(phy_id) | SMI_REGADDR(reg);

	mii->write(mii->dev, MARVELL_GLOBAL2, GLOBREG_SMI_DATA, val);
	mii->write(mii->dev, MARVELL_GLOBAL2, GLOBREG_SMI_CMD, smi_cmd);
	if (__mii_indirect_wait(mii, 1000) < 0) {
		printk(KERN_WARNING PFX "indirect phy write did not "
		       "complete.\n");
	}
}

static void mii_phy_write(struct mii_struct *mii, int phy_id, int reg, int val)
{

	if (mii->indirect_phy_access == false)
		return mii->write(mii->dev, phy_id, reg, val);
	else
		return __mii_indirect_write(mii, phy_id, reg, val);
}

static void __vtu_wait(struct mii_struct *mii)
{
	for (;;) {
		u16 val = mii->read(mii->dev, MARVELL_GLOBAL1, GLOBREG_VTUOP);
		if ((val & (1 << 15)) == 0)
			break;
		msleep(10);
	}
}

void fbxgw_sw_vtu_stu_init(struct mii_struct *mii, int port_state,
			   size_t nr_ports)
{
	u16 vtu_op = VTUOP_OP_STU_LOAD;
	u16 regs[2] = { 0 , 0 };
	int i;

	mii->write(mii->dev, MARVELL_GLOBAL1, GLOBREG_VTUOP, vtu_op);

	mii->write(mii->dev, MARVELL_GLOBAL1, GLOBREG_VTUSID, 0);
	mii->write(mii->dev, MARVELL_GLOBAL1, GLOBREG_VTUVID, VTUVID_VALID);


	for (i = 0; i < nr_ports; ++i) {
		int off;
		int shift;

		off = i / 4;
		shift = 4 * (i % 4) +  2;

		regs[off] |= port_state << shift;
	}

	mii->write(mii->dev, MARVELL_GLOBAL1, GLOBREG_VTU_P03_DATA, regs[0]);
	mii->write(mii->dev, MARVELL_GLOBAL1, GLOBREG_VTU_P46_DATA, regs[1]);

	vtu_op |= VTUOP_BUSY;
	mii->write(mii->dev, MARVELL_GLOBAL1, GLOBREG_VTUOP, vtu_op);
	__vtu_wait(mii);
}

void fbxgw_sw_vtu_load(struct mii_struct *mii, u16 vid, const u8 *ports,
		       size_t nr_ports)
{
	u16 vtu_op;
	u16 regs[2] = { 0, 0 };
	int i;

	vtu_op = VTUOP_OP_LOAD;
	mii->write(mii->dev, MARVELL_GLOBAL1, GLOBREG_VTUOP, vtu_op);

	mii->write(mii->dev, MARVELL_GLOBAL1, GLOBREG_VTUFID, 1);
	mii->write(mii->dev, MARVELL_GLOBAL1, GLOBREG_VTUSID, 0);

	mii->write(mii->dev, MARVELL_GLOBAL1, GLOBREG_VTUVID,
		   vid | VTUVID_VALID);

	for (i = 0; i < nr_ports; ++i) {
		int off;
		int shift;

		off = (i / 4);
		shift = (i % 4) * 4;

		regs[off] |= ports[i] << shift;
	}

	mii->write(mii->dev, MARVELL_GLOBAL1, GLOBREG_VTU_P03_DATA, regs[0]);
	mii->write(mii->dev, MARVELL_GLOBAL1, GLOBREG_VTU_P46_DATA, regs[1]);

	vtu_op |= VTUOP_BUSY;
	mii->write(mii->dev, MARVELL_GLOBAL1, GLOBREG_VTUOP, vtu_op);

	__vtu_wait(mii);
}

void fbxgw_sw_config_cpu_port(struct mii_struct *mii, int swport)
{
	u16 pcs = PCS_FORCEDUPLEX_FULL | PCS_FORCEDUPLEX |
		PCS_FORCESPEED_1000 |
		PCS_FORCELINK | PCS_FORCELINK_UP;

	if (mii->dev_id == 0x176)
		pcs |= PCS_RGMII_TX_DELAY | PCS_RGMII_RX_DELAY;
	else {
		static u16 delay;
		/*
		 * set rgmii delay for cpu port (5) and ftth port (4), also
		 * force ftth port in RGMII mode
		 */
		if (swport == 5)
			delay = P5_RGMII_DELAY;
		else
			delay = P4_RGMII_DELAY;
		mii->write(mii->dev, MARVELL_SWPORT4, 0x1a, 0x81e7);
		(void)mii->read(mii->dev, MARVELL_SWPORT5, 0x1a);
		mii->write(mii->dev, MARVELL_SWPORT5, 0x1a, P5_RGMII_DELAY);
		mii->write(mii->dev, MARVELL_SWPORT4, 0x1a, 0xc1e7);
	}

	mii->write(mii->dev, swport, PORTREG_PCS, pcs);
}

void fbxgw_sw_config_phy_port(struct mii_struct *mii, int phy_port)
{
	u16 val;

	if (mii->indirect_phy_access == false) {
		val = mii->read(mii->dev, MARVELL_GLOBAL1, GLOBREG_GCR);
		val &= ~GCR_PPUEN;
		mii->write(mii->dev, MARVELL_GLOBAL1, GLOBREG_GCR, val);
	}


	/* power up phy for eth port 0 */
	val = mii_phy_read(mii, phy_port, 0x00);
	val &= ~0x0800;
	mii_phy_write(mii, phy_port, 0x00, val);


	/* restart autoneg */
	val = mii_phy_read(mii, phy_port, 0x00);
	val |= 0x0200;
	mii_phy_write(mii, phy_port, 0x00, val);

	mii_phy_write(mii, phy_port, 20, 0);

	if (mii->indirect_phy_access == false) {
		val = mii->read(mii->dev, MARVELL_GLOBAL1, GLOBREG_GCR);
		val |= GCR_PPUEN;
		mii->write(mii->dev, MARVELL_GLOBAL1, GLOBREG_GCR, val);
	}
}

void fbxgw_sw_port_default_vid(struct mii_struct *mii, int swport, u16 vid)
{
	u16 val;

	val = mii->read(mii->dev, swport, PORTREG_VLANID);
	val &= ~0xfff;
	val |= vid;
	mii->write(mii->dev, swport, PORTREG_VLANID, val);
}

void fbxgw_sw_port_dot1q_secure(struct mii_struct *mii, int swport)
{
	u16 val;

	val = mii->read(mii->dev, swport, PORTREG_PCR2);
	val &= ~(3 << PCR2_MODE_SHIFT);
	val |= (PCR2_MODE_SECURE << PCR2_MODE_SHIFT);
	mii->write(mii->dev, swport, PORTREG_PCR2, val);
}

void fbxgw_sw_port_forward_enable(struct mii_struct *mii, int swport)
{
	u16 val;

	/* enable forwarding */
	val = mii->read(mii->dev, swport, PORTREG_PCR);
	val |= PCR_PORTSTATE_FORWARDING;
	mii->write(mii->dev, swport, PORTREG_PCR, val);
}
