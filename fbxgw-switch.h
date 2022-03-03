/*
 * fbxgw-switch.h for fbxgw-switch.h
 * Created by <nschichan@freebox.fr> on Tue Jun  5 20:46:37 2012
 */

#ifndef __FBXGW_SWITCH_H
# define __FBXGW_SWITCH_H

struct mii_struct {
	u16 dev_id;
	bool indirect_phy_access;
	struct net_device *dev;
	int (*read)(struct net_device *dev, int phy_id, int reg);
	void (*write)(struct net_device *dev, int phy_id, int reg, int val);
};

void fbxgw_sw_vtu_stu_init(struct mii_struct *mii, int port_state,
			   size_t nr_ports);

void fbxgw_sw_vtu_load(struct mii_struct *mii, u16 vid, const u8 *ports,
		       size_t nr_ports);

void fbxgw_sw_config_cpu_port(struct mii_struct *mii, int swport);

void fbxgw_sw_config_phy_port(struct mii_struct *mii, int phy_port);

void fbxgw_sw_port_default_vid(struct mii_struct *mii, int swport, u16 vid);

void fbxgw_sw_port_dot1q_secure(struct mii_struct *mii, int swport);

void fbxgw_sw_port_forward_enable(struct mii_struct *mii, int swport);

#define SWPORT(X)	((X) + 0x10)
#define PHYPORT(X)	(X)


#define PORTREG_SWITCH_IDENTIFIER	0x3
#define PRODUCT_NUM(x)			(((x) >> 4) & 0xfff)


#define PDATA_MEMBER_UNMODIFIED		0
#define PDATA_MEMBER_UNTAGGED		1
#define PDATA_MEMBER_TAGGED		2
#define PDATA_NOT_MEMBER		3

#define PCR_PORTSTATE_FORWARDING	3

int marvell_6176_config(struct net_device *dev, int probe,
			int (*mii_read)(struct net_device *dev,
					int phy_id, int reg),
			void (*mii_write)(struct net_device *dev,
					  int phy_id, int reg, int val));
int marvell_6161_config(struct net_device *dev, int probe,
			int (*mii_read)(struct net_device *dev,
					int phy_id, int reg),
			void (*mii_write)(struct net_device *dev,
					  int phy_id, int reg, int val));


#endif /* !__FBXGW_SWITCH_H */
