#ifndef _FBXBRIDGE_H
# define _FBXBRIDGE_H

#include <linux/if.h>
#include <linux/if_ether.h>

#define MAX_ALIASES		3

#define FBXBRIDGE_PFX		"fbxbridge: "

#define FBXBRIDGE_LAN_TO_WAN	1
#define FBXBRIDGE_WAN_TO_LAN	2

#define FBXBRIDGE_FLAGS_FILTER			(1 << 0)
#define FBXBRIDGE_FLAGS_DHCPD			(1 << 1)
#define FBXBRIDGE_FLAGS_NETFILTER		(1 << 2)

/*
 * ioctl command
 */

enum fbxbridge_ioctl_cmd
{
	E_CMD_BR_CHG = 0,
	E_CMD_BR_DEV_CHG,
	E_CMD_BR_PARAMS,
};

struct fbxbridge_ioctl_chg
{
	char	brname[IFNAMSIZ];
	int	action;
};

struct fbxbridge_ioctl_dev_chg
{
	char	brname[IFNAMSIZ];
	char	devname[IFNAMSIZ];
	int	wan;
	int	action;
};

struct fbxbridge_port_info
{
	char	name[IFNAMSIZ];
	int	present;
};

struct fbxbridge_ioctl_params
{
	int				action;
	char				brname[IFNAMSIZ];
	struct fbxbridge_port_info	wan_dev;
	struct fbxbridge_port_info	lan_dev;
	unsigned int			flags;
	unsigned char			lan_hwaddr[ETH_ALEN];
	unsigned char			have_hw_addr;
	unsigned int			dns1_addr;
	unsigned int			dns2_addr;
	unsigned long			ip_aliases[MAX_ALIASES];

	unsigned long			dhcpd_renew_time;
	unsigned long			dhcpd_rebind_time;
	unsigned long			dhcpd_lease_time;
	unsigned int			inputmark;
};

struct fbxbridge_ioctl_req
{
	enum fbxbridge_ioctl_cmd	cmd;
	unsigned long			arg;
};

#ifdef __KERNEL__

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>

#define ARP_RATE_LIMIT		(HZ)
#define ARP_ETHER_SIZE		(8 + ETH_ALEN * 2 + 4 * 2)

#define FBXBR_PORT_WAN		0
#define FBXBR_PORT_LAN		1

#define FBXBR_CACHE_SIZE	128
#define FBXBR_MAX_RULES		256

struct fbxbridge_port;

struct fbxbridge_fp_rule {
	u32			sip;
	u32			dip;
	u16			sport;
	u16			dport;

	u8			dest_hwaddr[6];
	struct fbxbridge_port	*oport;

	struct hlist_node	hnext;
	struct list_head	next;
};

struct fbxbridge_fp {
	struct hlist_head	hrules[FBXBR_CACHE_SIZE];
	struct list_head	rules;
	unsigned int		count;
};

struct fbxbridge_port {
	struct net_device	*dev;
	struct net_device	*master_dev;
	u16			vlan1;
	u16			vlan2;
	struct fbxbridge_fp	tcp_fp;
	struct fbxbridge_fp	udp_fp;
};

struct fbxbridge {
	struct fbxbridge	*next;
	unsigned int		refcount;

	char			name[IFNAMSIZ];
	struct net_device	*dev;

	/* local and remote (fbx) ip address */
	unsigned long		br_ipaddr;
	unsigned long		br_remote_ipaddr;

	/* list of ip we consider to be local */
	unsigned long		ip_aliases[MAX_ALIASES];

	/* wan side inet info */
	unsigned long		wan_ipaddr;
	unsigned long		wan_netmask;
	unsigned long		lan_netmask;
	/* this is the _client_ gw */
	unsigned long		wan_gw;

	char			wan_dev_name[IFNAMSIZ];
	char			lan_dev_name[IFNAMSIZ];
	int			fast_path_enabled;
	struct fbxbridge_port	ports[2];

	unsigned char		lan_hwaddr[ETH_ALEN];
	unsigned char		have_hw_addr;

	unsigned int		flags;
	unsigned int		inputmark;

	unsigned int		dns1_ipaddr;
	unsigned int		dns2_ipaddr;

	unsigned long		last_arp_send;

	unsigned long		dhcpd_renew_time;
	unsigned long		dhcpd_rebind_time;
	unsigned long		dhcpd_lease_time;
};

extern struct fbxbridge *fbxbridge_list;

/* fbxbridge_dev.c */
void __fbxbridge_keep_hw_addr(struct fbxbridge *br, unsigned char *hwaddr);

/* fbxbridge_dhcp.c */
void fbxbridge_dhcpd(struct fbxbridge *br, struct sk_buff *skb);


/* fbxbridge_forward.c */
struct sk_buff *fbxbridge_handle_frame(struct fbxbridge *br,
				       struct sk_buff *skb);


/* fbxbridge_filter.c */
int
fbxbridge_filter_lan_to_wan_packet(struct fbxbridge *br, struct sk_buff *skb);

int
fbxbridge_filter_wan_to_lan_packet(struct fbxbridge *br, struct sk_buff *skb);

int fbxbridge_nf_hook(struct fbxbridge *br, uint8_t pf, unsigned int hook,
		      struct sk_buff *skb, struct net_device *in,
		      struct net_device *out);

/* fbxbridge_local.c */
void
handle_local_input_lan_frame(struct fbxbridge *br, struct sk_buff *skb);

int
handle_local_output_frame(struct fbxbridge *br, struct sk_buff *skb);


/* fbxbridge_output.c */
void output_arp_frame(struct fbxbridge *br, struct net_device *dev,
		      unsigned short type,
		      unsigned long src_ip, unsigned char *src_hw,
		      unsigned long target_ip, unsigned char *target_hw);

void output_lan_frame(struct fbxbridge *br, struct sk_buff *skb);

void output_lan_mcast_frame(struct fbxbridge *br, struct sk_buff *skb);

void output_wan_frame(struct fbxbridge *br, struct sk_buff *skb);


/* fbxbridge_utils.c */
void fbxbridge_snat_packet(struct sk_buff *skb, unsigned long new_addr);

void fbxbridge_dnat_packet(struct sk_buff *skb, unsigned long new_addr);

int fbxbridge_check_ip_packet(struct sk_buff *skb);

int fbxbridge_check_udp_tcp_packet(struct sk_buff *skb);

/* fbxbridge_fastpath.c */
int __fbxbridge_fp_in_vlan_tcp4(struct net_device *idev, struct sk_buff *skb);

int __fbxbridge_fp_in_vlan_udp4(struct net_device *idev, struct sk_buff *skb);

int __fbxbridge_fp_add_wan_to_lan(struct fbxbridge *br,
				  const struct sk_buff *skb,
				  const uint8_t *new_dest_hw_addr);

int __fbxbridge_fp_add_lan_to_wan(struct fbxbridge *br,
				  const struct sk_buff *skb,
				  const uint8_t *new_dest_hw_addr);

void __fbxbridge_fp_flush_by_dip(struct fbxbridge_port *bport, uint32_t dip);

void __fbxbridge_fp_flush(struct fbxbridge *br);

void fbxbridge_fp_flush_all(void);

void fbxbridge_fp_init(struct fbxbridge *br);

void __fbxbridge_fp_check(struct fbxbridge *br);

#endif /* ! __KERNEL__ */

#endif
