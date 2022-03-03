/*
 * fbxgw-pcie.c for fbxgw
 * Created by <nschichan@freebox.fr> on Tue Jan 27 15:04:56 2015
 */

#include <linux/kernel.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/delay.h>

#include <asm/mach-types.h>

#define PFX	"fbxgw-pcie: "

# define PCIE0_PHYS	0xf1040000
# define PCIE1_PHYS	0xf1044000
# define CPUCFG_PHYS	0xf1020100

struct fbxgw_pcie_priv {
	void __iomem *cpuc_base; /* incl. CPU_CONTROL & CPU_CGC */
	void __iomem *pcie0_base;
	void __iomem *pcie1_base;
};

#define CPU_CONTROL		0x04
# define PCIE0_ENABLE		0x00000001
# define CPU_RESET		0x00000002
# define PCIE1_ENABLE		0x00000010

#define CLOCK_GATING_CTRL	0x1c
# define CGC_PEX0		(1 << 2)
# define CGC_PEX1		(1 << 18)

/*
 * PCIe unit register offsets.
 */
#define PCIE_DEV_ID_OFF		0x0000
#define PCIE_CMD_OFF		0x0004
#define PCIE_DEV_REV_OFF	0x0008
#define PCIE_BAR_LO_OFF(n)	(0x0010 + ((n) << 3))
#define PCIE_BAR_HI_OFF(n)	(0x0014 + ((n) << 3))
#define PCIE_LINK_CTRL_OFF	0x0070
#define  PCIE_LINK_CTRL_LINK_DIS	(1 << 4)
#define  PCIE_LINK_CTRL_RETR_LINK	(1 << 5)
#define  PCIE_LINK_CTRL_LINK_TRAINING	(1 << 27)
#define PCIE_HEADER_LOG_4_OFF	0x0128
#define PCIE_BAR_CTRL_OFF(n)	(0x1804 + ((n - 1) * 4))
#define PCIE_WIN04_CTRL_OFF(n)	(0x1820 + ((n) << 4))
#define PCIE_WIN04_BASE_OFF(n)	(0x1824 + ((n) << 4))
#define PCIE_WIN04_REMAP_OFF(n)	(0x182c + ((n) << 4))
#define PCIE_WIN5_CTRL_OFF	0x1880
#define PCIE_WIN5_BASE_OFF	0x1884
#define PCIE_WIN5_REMAP_OFF	0x188c
#define PCIE_CONF_ADDR_OFF	0x18f8
#define  PCIE_CONF_ADDR_EN		0x80000000
#define  PCIE_CONF_REG(r)		((((r) & 0xf00) << 16) | ((r) & 0xfc))
#define  PCIE_CONF_BUS(b)		(((b) & 0xff) << 16)
#define  PCIE_CONF_DEV(d)		(((d) & 0x1f) << 11)
#define  PCIE_CONF_FUNC(f)		(((f) & 0x7) << 8)
#define PCIE_CONF_DATA_OFF	0x18fc
#define PCIE_MASK_OFF		0x1910
#define PCIE_CTRL_OFF		0x1a00
#define  PCIE_CTRL_X1_MODE		0x0001
#define PCIE_STAT_OFF		0x1a04
#define  PCIE_STAT_DEV_OFFS		20
#define  PCIE_STAT_DEV_MASK		0x1f
#define  PCIE_STAT_BUS_OFFS		8
#define  PCIE_STAT_BUS_MASK		0xff
#define  PCIE_STAT_LINK_DOWN		1
#define PCIE_DEBUG_CTRL         0x1a60
#define  PCIE_DEBUG_SOFT_RESET		(1<<20)

static int __init pcie_link_up(void __iomem *base)
{
	return !(readl(base + PCIE_STAT_OFF) & PCIE_STAT_LINK_DOWN);
}

static void __init pcie_set_link_disable(void __iomem *base, int v)
{
	u32 val;

	val = readl(base + PCIE_LINK_CTRL_OFF);
	if (v)
		val |= PCIE_LINK_CTRL_LINK_DIS;
	else
		val &= ~PCIE_LINK_CTRL_LINK_DIS;
	writel(val, base + PCIE_LINK_CTRL_OFF);
}

static void __init pcie_set_retrain_link(void __iomem *base, int v)
{
	u32 val;

	val = readl(base + PCIE_LINK_CTRL_OFF);
	if (v)
		val |= PCIE_LINK_CTRL_RETR_LINK;
	else
		val &= ~PCIE_LINK_CTRL_RETR_LINK;
	writel(val, base + PCIE_LINK_CTRL_OFF);
}

static void __init __fbxgw_pcie_preinit(int index, void __iomem *base,
					struct fbxgw_pcie_priv *priv)
{
	u32 val;
	u32 pcie_enable_mask = index == 0 ? PCIE0_ENABLE : PCIE1_ENABLE;

	/* we will reset PCIe bus, make sure it's correctly disabled
	 * first */
	val = readl(priv->cpuc_base + CPU_CONTROL);
	if (!(val & pcie_enable_mask)) {
		val |= pcie_enable_mask;
		writel(val, priv->cpuc_base + CPU_CONTROL);
		return;
	}

	if (!pcie_link_up(base))
		return;

	pcie_set_link_disable(base, 1);
	mdelay(100);
	pcie_set_link_disable(base, 0);
}

int __init fbxgw_pcie_preinit(struct fbxgw_pcie_priv **out_priv)
{
	struct fbxgw_pcie_priv *priv;
	int err = -ENOMEM;
	priv = kzalloc(sizeof (*priv), GFP_KERNEL);

	if (!priv)
		return err;

	priv->cpuc_base = ioremap(CPUCFG_PHYS, 0x100);
	priv->pcie0_base = ioremap(PCIE0_PHYS, 0x4000);
	priv->pcie1_base = ioremap(PCIE1_PHYS, 0x4000);

	if (!priv->cpuc_base || !priv->pcie0_base || !priv->pcie1_base) {
		goto err_iounmap;
	}

	*out_priv = priv;

	__fbxgw_pcie_preinit(0, priv->pcie0_base, priv);
	if (machine_is_fbxgw2r())
		__fbxgw_pcie_preinit(1, priv->pcie1_base, priv);

	return 0;

err_iounmap:
	if (priv->cpuc_base)
		iounmap(priv->cpuc_base);
	if (priv->pcie0_base)
		iounmap(priv->pcie0_base);
	if (priv->pcie1_base)
		iounmap(priv->pcie1_base);
	return err;
}

static void __init __fbxgw_pcie_retrain_link(int index, void __iomem *base,
					     struct fbxgw_pcie_priv *priv)
{
	u32 cgc;

	/*
	 * be sure to enable corresponding PCIe clock. CGC_PEX0 might
	 * already be set due to previous call to kirkwood_pcie_id()
	 * though.
	 */
	cgc = readl(priv->cpuc_base + CLOCK_GATING_CTRL);
	switch (index) {
	case 0:
		cgc |= CGC_PEX0;
		break;
	case 1:
		cgc |= CGC_PEX1;
		break;
	}
	writel(cgc, priv->cpuc_base + CLOCK_GATING_CTRL);

	mdelay(100);
	pcie_set_retrain_link(base, 1);
	mdelay(1);
	/* check link, should be up */
	if (!pcie_link_up(base))
		pr_err(PFX "PCIe%d link is down\n", index);

}

void __init fbxgw_pcie_retrain_link(struct fbxgw_pcie_priv *priv)
{
	__fbxgw_pcie_retrain_link(0, priv->pcie0_base, priv);
	if (machine_is_fbxgw2r())
		__fbxgw_pcie_retrain_link(1, priv->pcie1_base, priv);
}

void __init fbxgw_pcie_preexit(struct fbxgw_pcie_priv *priv)
{
	iounmap(priv->pcie0_base);
	iounmap(priv->pcie1_base);
	iounmap(priv->cpuc_base);
}
