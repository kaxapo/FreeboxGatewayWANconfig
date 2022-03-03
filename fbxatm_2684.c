#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if_arp.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_sched.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/proc_fs.h>
#include <net/ip.h>
#include <net/route.h>
#include <linux/fbxatm_dev.h>

#include "fbxatm_priv.h"

#define PFX	"fbxatm_2684: "

static LIST_HEAD(fbxatm_2684_dev_list);
static DEFINE_MUTEX(fbxatm_2684_mutex);

#define LLC_NEEDED_HEADROOM		10
#define VCMUX_BRIDGED_NEEDED_HEADROOM	2

#define LLC			0xaa, 0xaa, 0x03
#define SNAP_BRIDGED		0x00, 0x80, 0xc2
#define SNAP_ROUTED		0x00, 0x00, 0x00
#define PID_ETHERNET_NOFCS	0x00, 0x07

static u8 llc_bridged_802d3_pad[] = { LLC, SNAP_BRIDGED, PID_ETHERNET_NOFCS,
				      0, 0 };
static u8 llc_snap_routed[] = { LLC, SNAP_ROUTED };

/*
 * private data for 2684 vcc
 */
struct fbxatm_2684_vcc;

struct fbxatm_2684_queue {
	struct fbxatm_vcc		*vcc;
	unsigned int			queue_idx;
	struct fbxatm_2684_vcc		*priv;
};

struct fbxatm_2684_vcc {
	struct fbxatm_2684_queue	queues[FBXATM_2684_MAX_VCC];
	size_t				queue_count;

	struct net_device		*dev;
	struct fbxatm_2684_vcc_params	params;

	spinlock_t			tx_lock;

	struct rtnl_link_stats64	stats;

	struct list_head		next;
};

static uint32_t tel_last_ip;

static void warn_if_tel(struct fbxatm_2684_vcc *vcc, struct sk_buff *skb)
{
	struct iphdr *iph;
	struct udphdr *udph = NULL;

	iph = (struct iphdr *)skb->data;

	if (iph->protocol != IPPROTO_UDP)
		return;

	if (skb_headlen(skb) < (iph->ihl * 4) + sizeof (struct udphdr))
		return;

	udph = (struct udphdr *)((unsigned char *)iph + (iph->ihl * 4));
	if (ntohs(udph->dest) >= 5004 && ntohs(udph->dest) <= 5020) {
		static u32 last_ip;
		static unsigned long last_time;
		unsigned long now;

		now = jiffies;
		if ((last_ip == iph->saddr &&
		     (!last_time || time_before(now, last_time + 2 * HZ)))) {
			static unsigned int consecutive;
			consecutive++;
			if (consecutive > 5) {
				tel_last_ip = iph->saddr;
				consecutive = 0;
			}
		}

		last_time = now;
		last_ip = iph->saddr;
	}
}

/*
 * procfs read callback
 */
static int tel_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%pI4\n", &tel_last_ip);
	return 0;
}

static int tel_proc_write(struct file *file, const char __user *ubuf,
			  size_t len, loff_t *off)
{
	tel_last_ip = 0;
	return len;
}

static int tel_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, tel_proc_show, PDE_DATA(inode));
}

static const struct file_operations tel_proc_fops = {
	.owner          = THIS_MODULE,
	.open           = tel_proc_open,
	.read           = seq_read,
	.write		= tel_proc_write,
	.llseek         = seq_lseek,
	.release        = single_release,
};

/*
 * fbxatm stack receive callback, called from softirq
 */
static void vcc_rx_callback(struct sk_buff *skb, void *data)
{
	struct fbxatm_2684_queue *queue;
	struct fbxatm_2684_vcc *priv;

	queue = (struct fbxatm_2684_queue *)data;
	priv = queue->priv;

	switch (priv->params.encap) {
	case FBXATM_E2684_VCMUX:
		switch (priv->params.payload) {
		case FBXATM_P2684_BRIDGE:
			/* assume 802.3, need to remove 2 bytes zero
			 * padding */
			if (skb->len < 2 || memcmp(skb->data, "\0\0", 2))
				goto drop;
			skb_pull(skb, 2);
			skb->protocol = eth_type_trans(skb, priv->dev);
			memset(skb->data, 0, 2);
			break;

		case FBXATM_P2684_ROUTED:
			/* assume ipv4 */
			skb->protocol = htons(ETH_P_IP);
			break;
		}
		break;

	case FBXATM_E2684_LLC:
		switch (priv->params.payload) {
		case FBXATM_P2684_BRIDGE:
		{
			/* recognize only 802.3 */
			if (skb->len < sizeof(llc_bridged_802d3_pad))
				goto drop;

			if (memcmp(skb->data, llc_bridged_802d3_pad, 7))
				goto drop;

			/* don't check the last bytes of pid, it can
			 * be 1 or 7 depending on the presence of
			 * FCS */
			skb_pull(skb, sizeof(llc_bridged_802d3_pad));
			skb->protocol = eth_type_trans(skb, priv->dev);
			break;
		}

		case FBXATM_P2684_ROUTED:
		{
			u16 proto;
			unsigned int offset;

			if (skb->len < sizeof(llc_snap_routed) + 2)
				goto drop;

			offset = sizeof (llc_snap_routed);
			proto = skb->data[offset] << 8;
			proto |= skb->data[offset + 1];

			skb->protocol = proto;
			skb_pull(skb, sizeof(llc_snap_routed) + 2);
			break;
		}
		}
		break;
	}

	skb->dev = priv->dev;
	skb->pkt_type = PACKET_HOST;
	priv->stats.rx_bytes += skb->len;
	priv->stats.rx_packets++;

	if (priv->params.encap == FBXATM_E2684_VCMUX &&
	    priv->params.payload == FBXATM_P2684_ROUTED &&
	    queue->vcc->vpi == 8 && queue->vcc->vci == 35)
		warn_if_tel(priv, skb);

	netif_rx(skb);
	return;

drop:
	priv->stats.rx_errors++;
	dev_kfree_skb(skb);
}

/*
 * fbxatm stack tx done callback, called from softirq
 */
static void vcc_tx_done_callback(void *data)
{
	struct fbxatm_2684_queue *queue;
	struct fbxatm_2684_vcc *priv;

	queue = (struct fbxatm_2684_queue *)data;
	priv = queue->priv;

	spin_lock(&priv->tx_lock);
	if (__netif_subqueue_stopped(priv->dev, queue->queue_idx))
		netif_wake_subqueue(priv->dev, queue->queue_idx);
	spin_unlock(&priv->tx_lock);
}

/*
 * fbxatm stack callback when vcc link changes
 */
static void vcc_link_change(void *data, int link,
			    unsigned int rx_cell_rate,
			    unsigned int tx_cell_rate)
{
	struct fbxatm_2684_queue *queue;
	struct fbxatm_2684_vcc *priv;

	queue = (struct fbxatm_2684_queue *)data;
	priv = queue->priv;

	if (link)
		netif_carrier_on(priv->dev);
	else
		netif_carrier_off(priv->dev);
}

/*
 * vcc user ops, callback from fbxatm stack
 */
static const struct fbxatm_vcc_uops fbxatm_2684_uops = {
	.link_change	= vcc_link_change,
	.rx_pkt		= vcc_rx_callback,
	.tx_done	= vcc_tx_done_callback,
};

/*
 * netdevice ->ndo_select_queue() callback
 */
static u16 fbxatm_2684_netdev_select_queue(struct net_device *dev,
					   struct sk_buff *skb,
					   void *accel_priv,
					   select_queue_fallback_t fallback)
{
	/* force lower band to avoid kernel doing round robin */
	return 0;
}

/*
 * netdevice xmit callback
 */
static int fbxatm_2684_netdev_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct fbxatm_2684_vcc *priv;
	int ret, queue_idx;
	unsigned int needed_headroom;
	struct fbxatm_2684_queue *queue;

	priv = netdev_priv(dev);
	queue_idx = skb_get_queue_mapping(skb);
	queue = &priv->queues[queue_idx];

	/*
	 * check if we have to expand skb head
	 */
	needed_headroom = 0;
	if (priv->params.encap == FBXATM_E2684_VCMUX) {
		if (priv->params.payload == FBXATM_P2684_BRIDGE)
			needed_headroom = VCMUX_BRIDGED_NEEDED_HEADROOM;
	} else
		needed_headroom = LLC_NEEDED_HEADROOM;

	if (skb_headroom(skb) < needed_headroom) {
		struct sk_buff *nskb;
		unsigned int new_head;

		new_head = skb_headroom(skb) + needed_headroom;
		nskb = skb_realloc_headroom(skb, new_head);
		dev_kfree_skb(skb);
		if (!nskb)
			goto dropped;
		skb = nskb;
	}

	switch (priv->params.encap) {
	case FBXATM_E2684_VCMUX:
		switch (priv->params.payload) {
		case FBXATM_P2684_BRIDGE:
			skb_push(skb, 2);
			memset(skb->data, 0, 2);
			break;
		case FBXATM_P2684_ROUTED:
			/* nothing to do */
			break;
		}
		break;

	case FBXATM_E2684_LLC:
		switch (priv->params.payload) {
		case FBXATM_P2684_BRIDGE:
			skb_push(skb, sizeof(llc_bridged_802d3_pad));
			memcpy(skb->data, llc_bridged_802d3_pad,
			       sizeof(llc_bridged_802d3_pad));
			break;

		case FBXATM_P2684_ROUTED:
		{
			unsigned int offset;

			skb_push(skb, sizeof(llc_snap_routed));
			memcpy(skb->data, llc_snap_routed,
			       sizeof(llc_snap_routed));

			offset = sizeof (llc_snap_routed);
			skb->data[offset] = (skb->protocol >> 8) & 0xff;
			skb->data[offset + 1] = skb->protocol & 0xff;
			break;
		}
		}
		break;
	}

	spin_lock(&priv->tx_lock);

	ret = fbxatm_send(queue->vcc, skb);
	if (ret) {
		/* packet was not sent, queue is full */
		netif_stop_subqueue(dev, queue_idx);
		spin_unlock(&priv->tx_lock);
		return NETDEV_TX_BUSY;
	}

	/* check if queue is full */
	priv->stats.tx_bytes += skb->len;
	priv->stats.tx_packets++;

	if (fbxatm_vcc_queue_full(queue->vcc))
		netif_stop_subqueue(dev, queue_idx);
	spin_unlock(&priv->tx_lock);

	return NETDEV_TX_OK;

dropped:
	priv->stats.tx_errors++;
	return NETDEV_TX_OK;
}

/*
 * netdevice get_stats callback
 */
static struct rtnl_link_stats64 *
fbxatm_2684_netdev_get_stats64(struct net_device *dev,
			       struct rtnl_link_stats64 *stats)
{
	struct fbxatm_2684_vcc *priv;
	priv = netdev_priv(dev);
	memcpy(stats, &priv->stats, sizeof (*stats));
	return stats;
}

/*
 * netdevice setup callback for bridge encap
 */
static void setup_bridged(struct net_device *dev)
{
	ether_setup(dev);
}

/*
 * netdevice setup callback for routed encap
 */
static void setup_routed(struct net_device *dev)
{
	dev->type		= ARPHRD_PPP;
	dev->hard_header_len	= 0;
	dev->mtu		= 1500;
	dev->addr_len		= 0;
	dev->tx_queue_len	= 128;
	dev->flags		= IFF_POINTOPOINT | IFF_NOARP | IFF_MULTICAST;
}

static const struct net_device_ops fbxatm_2684_ops = {
	.ndo_start_xmit		= fbxatm_2684_netdev_xmit,
	.ndo_get_stats64	= fbxatm_2684_netdev_get_stats64,
	.ndo_select_queue	= fbxatm_2684_netdev_select_queue,
};

/*
 * sysfs callback, show encapsulation
 */
static ssize_t show_encap(struct device *d,
			  struct device_attribute *attr, char *buf)
{
	struct fbxatm_2684_vcc *priv = netdev_priv(to_net_dev(d));

	switch (priv->params.encap) {
	case FBXATM_E2684_LLC:
		return sprintf(buf, "llc\n");
	case FBXATM_E2684_VCMUX:
	default:
		return sprintf(buf, "vcmux\n");
	}
}

static DEVICE_ATTR(encap, S_IRUGO, show_encap, NULL);

/*
 * sysfs callback, show payload
 */
static ssize_t show_payload(struct device *d,
			    struct device_attribute *attr, char *buf)
{
	struct fbxatm_2684_vcc *priv = netdev_priv(to_net_dev(d));

	switch (priv->params.payload) {
	case FBXATM_P2684_BRIDGE:
		return sprintf(buf, "bridge\n");
	case FBXATM_P2684_ROUTED:
	default:
		return sprintf(buf, "routed\n");
	}
}

static DEVICE_ATTR(payload, S_IRUGO, show_payload, NULL);

/*
 * sysfs callback, show vcc id
 */
static ssize_t show_vcc(struct device *d,
			struct device_attribute *attr, char *buf)
{
	struct fbxatm_2684_vcc *priv = netdev_priv(to_net_dev(d));

	return sprintf(buf, "%u.%u.%u\n",
		       priv->queues[0].vcc->adev->ifindex,
		       priv->queues[0].vcc->vpi, priv->queues[0].vcc->vci);
}

static DEVICE_ATTR(vcc, S_IRUGO, show_vcc, NULL);

static struct attribute *fbxatm2684_attrs[] = {
	&dev_attr_encap.attr,
	&dev_attr_payload.attr,
	&dev_attr_vcc.attr,
	NULL
};

static struct attribute_group fbxatm2684_group = {
	.name = "fbxatm2684",
	.attrs = fbxatm2684_attrs,
};

/*
 * create sysfs files for 2684 device
 */
static int vcc2684_sysfs_register(struct fbxatm_2684_vcc *priv,
				  struct net_device *dev)
{
	int ret;

	ret = sysfs_create_group(&dev->dev.kobj, &fbxatm2684_group);
	if (ret)
		goto out1;

	ret = sysfs_create_link(&dev->dev.kobj,
				&priv->queues[0].vcc->adev->dev.kobj,
				"fbxatm_dev");
	if (ret)
		goto out2;

	return 0;

out2:
	sysfs_remove_group(&dev->dev.kobj, &fbxatm2684_group);
out1:
	return ret;
}

/*
 * remove sysfs files for 2684 device
 */
static void vcc2684_sysfs_unregister(struct fbxatm_2684_vcc *priv,
				     struct net_device *dev)
{
	sysfs_remove_group(&dev->dev.kobj, &fbxatm2684_group);
	sysfs_remove_link(&dev->dev.kobj, "fbxatm_dev");
}

/*
 * register netdevice & sysfs attribute
 */
static int register_2684_netdev(struct fbxatm_2684_vcc *priv,
				struct net_device *dev)
{
	int ret;

	/* hold rtnl while registering netdevice and creating sysfs
	 * files to avoid race */
	rtnl_lock();

	if (strchr(dev->name, '%')) {
		ret = dev_alloc_name(dev, dev->name);
		if (ret < 0)
			goto out;
	}

	ret = register_netdevice(dev);
	if (ret)
		goto out;

	ret = vcc2684_sysfs_register(priv, dev);
	if (ret)
		goto out_unregister;

	rtnl_unlock();
	return 0;

out_unregister:
	unregister_netdevice(dev);

out:
	rtnl_unlock();
	return ret;
}

/*
 * create a RFC2684 encapsulation on given vcc
 */
static int __create_2684_vcc(const struct fbxatm_2684_vcc_params *params)
{
	struct fbxatm_2684_vcc *priv;
	struct fbxatm_vcc *vccs[FBXATM_2684_MAX_VCC];
	struct net_device *dev = NULL;
	void (*netdev_setup_cb)(struct net_device *dev);
	unsigned int headroom;
	size_t i;
	int ret;

	/* sanity check */
	switch (params->encap) {
	case FBXATM_E2684_VCMUX:
	case FBXATM_E2684_LLC:
		break;
	default:
		return -EINVAL;
	}

	switch (params->payload) {
	case FBXATM_P2684_BRIDGE:
		netdev_setup_cb = setup_bridged;
		break;
	case FBXATM_P2684_ROUTED:
		netdev_setup_cb = setup_routed;
		break;
	default:
		return -EINVAL;
	}

	if (!params->dev_name[0])
		return -EINVAL;

	/* bind to vcc */
	memset(vccs, 0, sizeof (vccs));
	for (i = 0; i < params->id_count; i++) {
		struct fbxatm_vcc *vcc;

		vcc = fbxatm_bind_to_vcc(&params->id_list[i],
					 FBXATM_VCC_USER_2684);
		if (IS_ERR(vcc)) {
			ret = PTR_ERR(vcc);
			goto fail;
		}
		vccs[i] = vcc;
	}

	/* create netdevice */
	dev = alloc_netdev_mqs(sizeof(*priv), params->dev_name,
			       NET_NAME_UNKNOWN, netdev_setup_cb,
			       params->id_count, 1);
	if (!dev) {
		ret = -ENOMEM;
		goto fail;
	}

	netif_set_real_num_tx_queues(dev, params->id_count);
	netif_set_real_num_rx_queues(dev, 1);

	priv = netdev_priv(dev);
	memset(priv, 0, sizeof (priv));
	memcpy(&priv->params, params, sizeof (*params));
	memcpy(dev->name, priv->params.dev_name, IFNAMSIZ);

	spin_lock_init(&priv->tx_lock);
	priv->dev = dev;
	for (i = 0; i < params->id_count; i++) {
		priv->queues[i].vcc = vccs[i];
		priv->queues[i].queue_idx = i;
		priv->queues[i].priv = priv;
	}
	priv->queue_count = params->id_count;

	dev->netdev_ops = &fbxatm_2684_ops;

	/* make sure kernel generated packet have correct headroom for
	 * encapsulation/payload */
	headroom = 0;
	for (i = 0; i < params->id_count; i++)
		headroom = max_t(int, headroom, vccs[i]->adev->tx_headroom);
	dev->hard_header_len += headroom;

	switch (params->encap) {
	case FBXATM_E2684_VCMUX:
	default:
		if (params->payload == FBXATM_P2684_BRIDGE)
			dev->hard_header_len += VCMUX_BRIDGED_NEEDED_HEADROOM;
		break;
	case FBXATM_E2684_LLC:
		dev->hard_header_len += LLC_NEEDED_HEADROOM;
		break;
	}

	ret = register_2684_netdev(priv, dev);
	if (ret)
		goto fail;

	if (fbxatm_vcc_link_is_up(vccs[0])) {
		netif_carrier_on(dev);
		netif_tx_start_all_queues(dev);
	} else
		netif_carrier_off(dev);
	list_add_tail(&priv->next, &fbxatm_2684_dev_list);

	for (i = 0; i < params->id_count; i++)
		fbxatm_set_uops(vccs[i], &fbxatm_2684_uops, &priv->queues[i]);

	return 0;

fail:
	for (i = 0; i < ARRAY_SIZE(vccs); i++) {
		if (vccs[i])
			fbxatm_unbind_vcc(vccs[i]);
	}
	if (dev)
		free_netdev(dev);
	return ret;
}

/*
 * find 2684 vcc from id list
 */
static struct fbxatm_2684_vcc *__find_2684_vcc(const struct fbxatm_vcc_id *id,
					       size_t count)
{
	struct fbxatm_2684_vcc *priv;
	size_t i;

	/* find it */
	list_for_each_entry(priv, &fbxatm_2684_dev_list, next) {
		for (i = 0; i < priv->queue_count; i++) {
			struct fbxatm_2684_queue *q;
			size_t j;

			q = &priv->queues[i];

			for (j = 0; j < count; j++) {
				if (q->vcc->adev->ifindex == id[j].dev_idx &&
				    q->vcc->vpi == id[0].vpi &&
				    q->vcc->vci == id[0].vci)
					return priv;
			}
		}
	}
	return NULL;
}

/*
 * create a RFC2684 encapsulation on given vcc
 */
static int create_2684_vcc(const struct fbxatm_2684_vcc_params *params)
{
	int ret;

	mutex_lock(&fbxatm_2684_mutex);
	ret = __create_2684_vcc(params);
	mutex_unlock(&fbxatm_2684_mutex);
	return ret;
}

/*
 * remove RFC2684 encapsulation from given vcc
 */
static int __remove_2684_vcc(const struct fbxatm_2684_vcc_params *params)
{
	struct fbxatm_2684_vcc *priv;
	size_t i;

	priv = __find_2684_vcc(params->id_list, params->id_count);
	if (!priv)
		return -ENOENT;

	/* close netdevice, fbxatm_2684_netdev_xmit cannot be called
	 * again */
	rtnl_lock();
	dev_close(priv->dev);
	rtnl_unlock();

	for (i = 0; i < priv->queue_count; i++)
		fbxatm_unbind_vcc(priv->queues[i].vcc);
	vcc2684_sysfs_unregister(priv, priv->dev);
	unregister_netdev(priv->dev);
	list_del(&priv->next);
	free_netdev(priv->dev);
	return 0;
}

/*
 * remove RFC2684 encapsulation from given vcc
 */
static int remove_2684_vcc(const struct fbxatm_2684_vcc_params *params)
{
	int ret;

	mutex_lock(&fbxatm_2684_mutex);
	ret = __remove_2684_vcc(params);
	mutex_unlock(&fbxatm_2684_mutex);
	return ret;
}

/*
 * 2684 related ioctl handler
 */
static int fbxatm_2684_ioctl(struct socket *sock,
			     unsigned int cmd, void __user *useraddr)
{
	int ret;

	ret = 0;

	switch (cmd) {
	case FBXATM_2684_IOCADD:
	case FBXATM_2684_IOCDEL:
	{
		struct fbxatm_2684_vcc_params params;

		if (copy_from_user(&params, useraddr, sizeof(params)))
			return -EFAULT;

		if (cmd == FBXATM_2684_IOCADD)
			ret = create_2684_vcc(&params);
		else
			ret = remove_2684_vcc(&params);
		break;
	}

	case FBXATM_2684_IOCGET:
	{
		struct fbxatm_2684_vcc_params params;
		struct fbxatm_2684_vcc *priv;

		if (copy_from_user(&params, useraddr, sizeof(params)))
			return -EFAULT;

		mutex_lock(&fbxatm_2684_mutex);
		priv = __find_2684_vcc(params.id_list, params.id_count);
		if (!priv)
			ret = -ENOENT;
		else {
			memcpy(&params, &priv->params, sizeof (params));
			memcpy(params.dev_name, priv->dev->name, IFNAMSIZ);
		}
		mutex_unlock(&fbxatm_2684_mutex);

		if (ret)
			return ret;

		if (copy_to_user(useraddr, &params, sizeof(params)))
			return -EFAULT;
		break;
	}

	default:
		return -ENOIOCTLCMD;
	}

	return ret;
}

static struct fbxatm_ioctl fbxatm_2684_ioctl_ops = {
	.handler	= fbxatm_2684_ioctl,
	.owner		= THIS_MODULE,
};

int __init fbxatm_2684_init(void)
{
	struct proc_dir_entry *root, *proc;

	root = fbxatm_proc_misc_register("tel");
	if (!root)
		return -ENOMEM;

	/* tel debug crap */
	proc = proc_create_data("bad_ip", 0666, root, &tel_proc_fops, NULL);
	if (!proc)
		return -ENOMEM;

	fbxatm_register_ioctl(&fbxatm_2684_ioctl_ops);
	return 0;
}

void fbxatm_2684_exit(void)
{
	fbxatm_unregister_ioctl(&fbxatm_2684_ioctl_ops);
}
