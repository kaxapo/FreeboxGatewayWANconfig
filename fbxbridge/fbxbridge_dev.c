
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/sockios.h>

#include <linux/notifier.h>
#include <linux/if_arp.h>
#include <linux/inetdevice.h>
#include <asm/uaccess.h>

#include <linux/fbxbridge.h>
#include <linux/if_vlan.h>
#include <net/neighbour.h>
#include <net/netevent.h>

struct fbxbridge *fbxbridge_list = NULL;
extern struct sk_buff *(*fbxbridge_handle_frame_hook)(struct fbxbridge *br,
						      struct sk_buff *skb);
extern void fbxbridge_set(int (*hook)(struct net *net,
				      unsigned int, void __user *));

/*
 * bridge network function
 */
static int bridge_net_open(struct net_device *dev)
{
	return 0;
}

static int bridge_net_stop(struct net_device *dev)
{
	return 0;
}


#define	DEFAULT_RENEWAL_TIME	60
#define	DEFAULT_REBIND_TIME	300
#define	DEFAULT_LEASE_TIME	600


static int bridge_net_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct fbxbridge *br = (struct fbxbridge *)netdev_priv(dev);

	br->dev->stats.tx_packets++;
	br->dev->stats.tx_bytes += skb->len;

	if (handle_local_output_frame(br, skb))
		br->dev->stats.tx_dropped++;

	return 0;
}

static const struct net_device_ops fbxbridge_net_ops = {
	.ndo_open		= bridge_net_open,
	.ndo_stop		= bridge_net_stop,
	.ndo_start_xmit		= bridge_net_start_xmit,
};

static void bridge_net_setup(struct net_device *dev)
{
	dev->netdev_ops = &fbxbridge_net_ops;
	dev->flags = IFF_NOARP;
	dev->tx_queue_len = 0;	/* we use bridge devices queues */
	dev->type = ARPHRD_PPP;
	dev->mtu = 1500;
	dev->features = 0;
	dev->hard_header_len = 16;
}

/*
 * helper to access the bridge list
 */
static void add_to_bridge_list(struct fbxbridge *br)
{
	br->next = fbxbridge_list;
	fbxbridge_list = br;
}

static void remove_from_bridge_list(struct fbxbridge *br)
{
	struct fbxbridge *p, *pprev;

	pprev = p = fbxbridge_list;
	while (p) {
		if (p == br)
			break;
		pprev = p;
	}

	if (p) {
		if (p == fbxbridge_list)
			fbxbridge_list = fbxbridge_list->next;
		else
			pprev->next = br->next;
	}
}

static struct fbxbridge *get_bridge_by_name(const char *name)
{
	struct fbxbridge *p;

	p = fbxbridge_list;
	while (p) {
		if (!strcmp(name, p->name))
			return p;
		p = p->next;
	}

	return NULL;
}

static struct fbxbridge *alloc_bridge(const char *name)
{
	struct net_device *dev;
	struct fbxbridge *br;

	dev = alloc_netdev(sizeof(*br), name, NET_NAME_UNKNOWN,
			   bridge_net_setup);
	if (!dev)
		return NULL;
	br = netdev_priv(dev);

	memset(br, 0, sizeof (*br));
	strncpy(br->name, name, IFNAMSIZ);
	br->refcount = 1;
	br->last_arp_send = jiffies;
	br->dev = dev;

	br->dhcpd_renew_time = DEFAULT_RENEWAL_TIME;
	br->dhcpd_rebind_time = DEFAULT_REBIND_TIME;
	br->dhcpd_lease_time = DEFAULT_LEASE_TIME;

	fbxbridge_fp_init(br);

	return br;
}

static struct net_device *get_vlan_master(struct net_device *dev,
					  u16 *id, u16 *id2)
{
	struct net_device *sub_dev, *sub2_dev;

	if (!is_vlan_dev(dev)) {
		*id = 0;
		*id2 = 0;
		return dev;

	}

	sub_dev = vlan_dev_upper_dev(dev);
	if (!is_vlan_dev(sub_dev)) {
		*id = vlan_dev_vlan_id(dev);
		*id2 = 0;
		return sub_dev;
	}

	/* subdevice is a vlan too */
	sub2_dev = vlan_dev_upper_dev(sub_dev);
	*id = vlan_dev_vlan_id(sub_dev);
	*id2 = vlan_dev_vlan_id(dev);

	return sub2_dev;
}

static void
__grab_bridge_device(struct fbxbridge *br,
		     struct net_device *dev,
		     bool is_wan)
{
	struct fbxbridge_port *bport;
	u16 id, id2;

	bport = &br->ports[is_wan ? FBXBR_PORT_WAN : FBXBR_PORT_LAN];
	if (bport->dev)
		return;

	dev_hold(dev);
	dev->fbx_bridge_port = br;
	bport->dev = dev;
	bport->master_dev = get_vlan_master(dev, &id, &id2);
	bport->master_dev->fbx_bridge_maybe_port++;
	bport->vlan1 = id;
	bport->vlan2 = id2;

	printk(KERN_INFO "%s: %s device %s grabbed - master %s\n",
	       br->name, is_wan ? "wan" : "lan", dev->name,
	       bport->master_dev->name);

	__fbxbridge_fp_check(br);
}

static void
__ungrab_bridge_device(struct fbxbridge *br, bool is_wan)
{
	struct net_device *dev;
	struct fbxbridge_port *bport;

	bport = &br->ports[is_wan ? FBXBR_PORT_WAN : FBXBR_PORT_LAN];
	if (!bport->dev)
		return;

	dev = bport->dev;
	bport->dev = NULL;
	bport->master_dev->fbx_bridge_maybe_port--;
	bport->master_dev = NULL;

	if (!is_wan)
		br->have_hw_addr = 0;

	dev->fbx_bridge_port = NULL;
	dev_put(dev);

	printk(KERN_INFO "%s: %s device %s released\n",
	       br->name, is_wan ? "wan" : "lan", dev->name);

	__fbxbridge_fp_check(br);
}

static int release_bridge(struct fbxbridge *br)
{
	if (--br->refcount > 0)
		return 0;

	/*
	 * allow removal of bridge even if there are devices present
	 * in it.
	 */
	if (br->ports[FBXBR_PORT_WAN].dev)
		__ungrab_bridge_device(br, true);
	if (br->ports[FBXBR_PORT_LAN].dev)
		__ungrab_bridge_device(br, false);

	printk(KERN_INFO FBXBRIDGE_PFX "unregistering bridge %s\n", br->name);

	br->dev->fbx_bridge = NULL;
	wmb();
	unregister_netdev(br->dev);
	remove_from_bridge_list(br);
	free_netdev(br->dev);

	module_put(THIS_MODULE);

	return 0;
}

static int remove_bridge(const char *name)
{
	struct fbxbridge *br;

	if (!(br = get_bridge_by_name(name)))
		return -ENODEV;

	return release_bridge(br);
}

static int create_bridge(const char *name)
{
	struct fbxbridge *br;

	if (get_bridge_by_name(name))
		return -EEXIST;

	/* allocate this bridge */
	if (!(br = alloc_bridge(name)))
		return -ENOMEM;

	if (register_netdev(br->dev)) {
		free_netdev(br->dev);
		return -ENODEV;
	}

	br->dev->fbx_bridge = br;
	add_to_bridge_list(br);

	/* can not fail, the ioctl hook is protected by a mutex */
	try_module_get(THIS_MODULE);

	printk(KERN_INFO FBXBRIDGE_PFX "registered bridge %s\n", name);

	return 0;
}

static int set_bridge_info(const char *name, unsigned int flags,
			   unsigned int dns1, unsigned int dns2,
			   unsigned long *ip_aliases,
			   unsigned long dhcpd_renew_time,
			   unsigned long dhcpd_rebind_time,
			   unsigned long dhcpd_lease_time,
			   unsigned int inputmark)
{
	struct fbxbridge *br;

	if (!(br = get_bridge_by_name(name)))
		return -ENODEV;

	local_bh_disable();
	br->flags = flags;
	br->dns1_ipaddr = dns1;
	br->dns2_ipaddr = dns2;
	memcpy(br->ip_aliases, ip_aliases, sizeof (br->ip_aliases));
	br->dhcpd_renew_time = dhcpd_renew_time;
	br->dhcpd_rebind_time = dhcpd_rebind_time;
	br->dhcpd_lease_time = dhcpd_lease_time;
	br->inputmark = inputmark;
	local_bh_enable();

	return 0;
}



static int find_bridge_interface(const char *dev_name, struct fbxbridge **br)
{
	struct fbxbridge *p;

	p = fbxbridge_list;
	while (p) {

		if (strcmp(p->name, dev_name)) {
			p = p->next;
			continue;
		}

		if (br)
			*br = p;
		return 1;
	}

	return 0;
}

static int find_bridge_device(const char *dev_name, struct fbxbridge **br,
			      bool *is_wan)
{
	struct fbxbridge *p;

	p = fbxbridge_list;
	while (p) {
		if (!strcmp(p->lan_dev_name, dev_name)) {
			if (br)
				*br = p;
			if (is_wan)
				*is_wan = 0;
			return 1;
		}
		if (!strcmp(p->wan_dev_name, dev_name)) {
			if (br)
				*br = p;
			if (is_wan)
				*is_wan = 1;
			return 1;
		}
		p = p->next;
	}

	return 0;
}

static inline __be32 gen_wan_gw(__be32 be_ipaddr, __be32 be_netmask)
{
	u32 ipaddr, netmask;
	u32 gw, mask;

	ipaddr = __be32_to_cpu(be_ipaddr);
	netmask = __be32_to_cpu(be_netmask);

	gw = ipaddr & netmask;
	mask = ~netmask;

	gw |= (mask - 1);
	if (gw == ipaddr) {
		/*
		 * that's unfortunate, but when in PPP mode, the
		 * computed gateway can be the public ip address of
		 * the customer. nevermind, pick the .253 address,
		 * gateway ip is just a polite jocke in PPP anyway.
		 */
		gw &= netmask;
		gw |= mask - 2;
	}
	return __cpu_to_be32(gw);
}

/*
 * assume it is running with bh disabled
 */
static void __fetch_wan_addr(struct fbxbridge *br, struct in_ifaddr *ifa)
{
	struct net_device *dev;
	int changed;

	if (ifa) {
		changed = 0;
		dev = ifa->ifa_dev->dev;

		if (br->wan_ipaddr != ifa->ifa_local ||
		    br->wan_netmask != ifa->ifa_mask)
			changed = 1;

		br->wan_ipaddr = ifa->ifa_local;
		br->wan_netmask = ifa->ifa_mask;
		if (br->wan_netmask != 0xffffffff) {
			br->wan_gw = gen_wan_gw(br->wan_ipaddr, br->wan_netmask);
			br->lan_netmask = br->wan_netmask;
		} else {
			u32 gw;

			gw = ntohl(br->wan_ipaddr) & 0xffffff00;
			if ((gw | 0xfe) == ntohl(br->wan_ipaddr))
				gw |= 0xfd;
			else
				gw |= 0xfe;

			br->wan_gw = htonl(gw);
			br->lan_netmask = htonl(0xffffff00);
		}

		if (changed) {
			printk(KERN_NOTICE "%s: wan inet device %s address "
			       "changed to [%pI4]\n", br->name,
 			       dev->name, &br->wan_ipaddr);
			printk("%s: %s: wan netmask: %pI4\n",
			       br->name, dev->name, &br->wan_netmask);
			printk("%s: %s: wan gw: %pI4\n",
			       br->name, dev->name, &br->wan_gw);
			__fbxbridge_fp_check(br);
		}
	}
}

void __fbxbridge_keep_hw_addr(struct fbxbridge *br, unsigned char *hwaddr)
{
	if (br->have_hw_addr && !memcmp(br->lan_hwaddr, hwaddr, ETH_ALEN))
		return;

	if (br->have_hw_addr)
		__fbxbridge_fp_flush(br);

	memcpy(br->lan_hwaddr, hwaddr, ETH_ALEN);
	br->have_hw_addr = 1;
	printk(KERN_NOTICE "%s: new lan hw address is now %pM\n",
	       br->name, hwaddr);
	__fbxbridge_fp_check(br);
}

static int add_bridge_device(const char *bridge_name, const char *dev_name,
			     bool is_wan)
{
	struct net_device *dev;
	struct fbxbridge *br;

	/* check no bridge already use this device */
	if (find_bridge_device(dev_name, NULL, NULL))
		return -EEXIST;

	if (!(br = get_bridge_by_name(bridge_name)))
		return -ENODEV;

	/* any room for a new device */
	if (is_wan) {
		if (br->wan_dev_name[0])
			return -EBUSY;

		strcpy(br->wan_dev_name, dev_name);
	} else {
		if (br->lan_dev_name[0])
			return -EBUSY;

		strcpy(br->lan_dev_name, dev_name);
	}

	/* try to resolve device */
	if (!(dev = dev_get_by_name(&init_net, dev_name))) {
		/* device does  not exists  yet, will wait  for device
		 * events */
		return 0;
	}

	local_bh_disable();
	__grab_bridge_device(br, dev, is_wan);
	if (is_wan) {
		struct in_device *in_dev;

		rcu_read_lock();

		in_dev = __in_dev_get_rcu(dev);
		if (in_dev)
			__fetch_wan_addr(br, in_dev->ifa_list);

		rcu_read_unlock();
	}
	local_bh_enable();
	dev_put(dev);

	return 0;
}

static int remove_bridge_device(const char *bridge_name, const char *dev_name)
{
	struct fbxbridge *br;
	bool is_wan;

	/* check bridge use this device */
	if (!find_bridge_device(dev_name, &br, &is_wan))
		return -ENODEV;

	/* is this the one ? */
	if (strcmp(bridge_name, br->name))
		return -ENODEV;

	local_bh_disable();
	__ungrab_bridge_device(br, is_wan);
	if (is_wan)
		br->wan_dev_name[0] = 0;
	else
		br->lan_dev_name[0] = 0;
	local_bh_enable();

	return 0;
}



static int bridge_device_event(struct notifier_block *this,
			       unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct fbxbridge *br;
	bool is_wan;

	/* only interested by device that belong to a bridge */
	if (!find_bridge_device(dev->name, &br, &is_wan))
		return NOTIFY_DONE;

	local_bh_disable();

	switch (event) {
	case NETDEV_UP:
		__grab_bridge_device(br, dev, is_wan);
		break;

	case NETDEV_GOING_DOWN:
	case NETDEV_DOWN:
	case NETDEV_UNREGISTER:
		__ungrab_bridge_device(br, is_wan);
		break;

	default:
		break;
	};

	local_bh_enable();

	return NOTIFY_DONE;
}

/*
 * handle inet configuration event on bridge interface (fbxbr%d)
 */
static void bridge_inet_interface_event(struct fbxbridge *br,
					unsigned long event,
					struct in_ifaddr *ifa)
{
	int changed = 0;

	switch (event) {
	case NETDEV_UP:
		local_bh_disable();
		if (ifa->ifa_address && ifa->ifa_local != ifa->ifa_address) {
			br->br_ipaddr = ifa->ifa_local;
			br->br_remote_ipaddr = ifa->ifa_address;
			changed = 1;
			__fbxbridge_fp_check(br);
		}
		local_bh_enable();
		break;

	case NETDEV_DOWN:
		local_bh_disable();
		if (br->br_ipaddr) {
			br->br_ipaddr = br->br_remote_ipaddr = 0;
			changed = 1;
			__fbxbridge_fp_check(br);
		}
		local_bh_enable();
		break;

	default:
		return;
	}

	if (!changed)
		return;

	if (br->br_ipaddr) {
		printk(KERN_INFO "%s: bridge interface configured: "
		       "[%pI4 -> %pI4]\n", br->name,
		       &br->br_ipaddr, &br->br_remote_ipaddr);
	} else {
		printk(KERN_INFO "%s: bridge interface unconfigured\n",
		       br->name);
	}
}

/*
 * handle inet configuration event on bridge wan device
 */
static void bridge_inet_device_event(struct fbxbridge *br, unsigned long event,
				     struct in_ifaddr *ifa)
{
	switch (event) {
	case NETDEV_UP:
		local_bh_disable();
		__fetch_wan_addr(br, ifa);
		local_bh_enable();
		break;

	case NETDEV_DOWN:
		/* we never  clear wan address, so we  can continue to
		 * use the bridge on lan side even if wan is down */
		break;

	default:
		break;
	}
}


static int bridge_inet_event(struct notifier_block *this,
			     unsigned long event, void *ptr)
{
	struct in_ifaddr *ifa = (struct in_ifaddr *)ptr;
	struct net_device *dev = ifa->ifa_dev->dev;
	struct fbxbridge *br;

	/* is it a bridge or a wan device that belong to a bridge ? */
	if (find_bridge_interface(dev->name, &br))
		bridge_inet_interface_event(br, event, ifa);
	else {
		bool is_wan;

		if (find_bridge_device(dev->name, &br, &is_wan) && is_wan)
			bridge_inet_device_event(br, event, ifa);
	}

	return NOTIFY_DONE;
}


static struct notifier_block fbxbridge_notifier = {
	notifier_call: bridge_device_event,
};

static struct notifier_block fbxbridge_inet_notifier = {
	notifier_call: bridge_inet_event,
};


/* ioctl handling */
static int fbxbridge_ioctl(struct net *net, unsigned int ign, void __user *arg)
{
	struct fbxbridge_ioctl_req	req;
	struct fbxbridge_ioctl_chg	chg;
	struct fbxbridge_ioctl_dev_chg	dev_chg;
	struct fbxbridge_ioctl_params	params;
	struct fbxbridge		*br;
	int				ret;

	/* fetch ioctl request */
	if (access_ok(VERIFY_READ, arg, sizeof(req)) != 1)
		return -EFAULT;

	if (copy_from_user(&req, arg, sizeof (req)))
		return -EFAULT;

	switch (req.cmd) {
	case E_CMD_BR_CHG:
		if (access_ok(VERIFY_READ, (void *)req.arg, sizeof(chg)) != 1)
			return -EFAULT;

		if (copy_from_user(&chg, (void *)req.arg, sizeof (chg)))
			return -EFAULT;

		if (!capable(CAP_NET_ADMIN))
			return -EPERM;

		if (!chg.action)
			return create_bridge(chg.brname);
		return remove_bridge(chg.brname);

	case E_CMD_BR_DEV_CHG:
		if (access_ok(VERIFY_READ, (void *)req.arg,
			      sizeof(dev_chg)) != 1)
			return -EFAULT;

		if (copy_from_user(&dev_chg, (void *)req.arg,
				   sizeof (dev_chg)))
			return -EFAULT;

		if (!capable(CAP_NET_ADMIN))
			return -EPERM;

		if (!dev_chg.action)
			return add_bridge_device(dev_chg.brname,
						 dev_chg.devname,
						 dev_chg.wan ? 1 : 0);

		return remove_bridge_device(dev_chg.brname, dev_chg.devname);

	case E_CMD_BR_PARAMS:
		if (access_ok(VERIFY_READ, (void *)req.arg,
			      sizeof(params)) != 1)
			return -EFAULT;

		if (copy_from_user(&params, (void *)req.arg, sizeof (params)))
			return -EFAULT;

		if (!params.action) {
			/* this is a get */
			if (!(br = get_bridge_by_name(params.brname)))
				return -ENODEV;

			local_bh_disable();

			params.flags = br->flags;
			params.dns1_addr = br->dns1_ipaddr;
			params.dns2_addr = br->dns2_ipaddr;
			params.have_hw_addr = br->have_hw_addr;
			memcpy(params.ip_aliases, br->ip_aliases,
			       sizeof (br->ip_aliases));
			memcpy(params.lan_hwaddr, br->lan_hwaddr, ETH_ALEN);

			memcpy(params.wan_dev.name, br->wan_dev_name,
			       IFNAMSIZ);
			if (br->ports[FBXBR_PORT_WAN].dev)
				params.wan_dev.present = 1;

			memcpy(params.lan_dev.name, br->lan_dev_name,
			       IFNAMSIZ);
			if (br->ports[FBXBR_PORT_LAN].dev)
				params.lan_dev.present = 1;

			params.dhcpd_renew_time = br->dhcpd_renew_time;
			params.dhcpd_rebind_time = br->dhcpd_rebind_time;
			params.dhcpd_lease_time = br->dhcpd_lease_time;
			params.inputmark = br->inputmark;
			local_bh_enable();

			if (access_ok(VERIFY_WRITE, (void *)req.arg,
				      sizeof(params)) != 1)
				return -EFAULT;

			if (copy_to_user((void *)req.arg, &params,
					 sizeof (params)))
				return -EFAULT;
			return 0;
		}

		/* this is a set */
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;

		local_bh_disable();
		ret = set_bridge_info(params.brname, params.flags,
				      params.dns1_addr, params.dns2_addr,
				      params.ip_aliases,
				      params.dhcpd_renew_time,
				      params.dhcpd_rebind_time,
				      params.dhcpd_lease_time,
				      params.inputmark);
		local_bh_enable();

		return ret;

	default:
		return -EINVAL;
	}

	return 0;
}

static int fbxbridge_netevent_callback(struct notifier_block *nb,
				       unsigned long event,
				       void *data)
{
	struct neighbour *n;
	struct fbxbridge *p;
	u32 dip;

	if (event != NETEVENT_NEIGH_UPDATE)
		return 0;

	n = (struct neighbour *)data;
	if (n->nud_state & NUD_VALID)
		return 0;

	if (n->tbl->family != AF_INET)
		return 0;

	memcpy(&dip, n->primary_key, 4);

	local_bh_disable();
	p = fbxbridge_list;
	while (p) {
		unsigned int i;

		for (i = 0; i < ARRAY_SIZE(p->ports); i++) {
			if (p->ports[i].dev != n->dev)
				continue;

			__fbxbridge_fp_flush_by_dip(&p->ports[i], dip);
			goto found;
		}

		p = p->next;
	}

found:
	local_bh_enable();
	return 0;
}

static struct notifier_block fbxbridge_netevent_nb = {
        .notifier_call = fbxbridge_netevent_callback,
};

static int __init fbxbridge_init_module(void)
{
	register_netdevice_notifier(&fbxbridge_notifier);
	register_inetaddr_notifier(&fbxbridge_inet_notifier);
	register_netevent_notifier(&fbxbridge_netevent_nb);
	fbxbridge_handle_frame_hook = fbxbridge_handle_frame;
	fbxbridge_set(fbxbridge_ioctl);

	return 0;
}

static void __exit fbxbridge_exit_module(void)
{
	unregister_netdevice_notifier(&fbxbridge_notifier);
	unregister_netevent_notifier(&fbxbridge_netevent_nb);
	unregister_inetaddr_notifier(&fbxbridge_inet_notifier);
	fbxbridge_set(NULL);
	fbxbridge_handle_frame_hook = NULL;
}

module_init(fbxbridge_init_module);
module_exit(fbxbridge_exit_module);

MODULE_AUTHOR("Maxime Bizon <mbizon@freebox.fr>");
MODULE_DESCRIPTION("Freebox Network Bridge - www.freebox.fr");
MODULE_LICENSE("GPL");
