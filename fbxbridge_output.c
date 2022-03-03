
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/init.h>

#include <linux/timer.h>
#include <linux/ip.h>
#include <linux/if_arp.h>
#include <net/ip.h>
#include <net/arp.h>

#include <linux/fbxbridge.h>

static unsigned char hw_bcast[ETH_ALEN] = { 0xff, 0xff, 0xff,
					    0xff, 0xff, 0xff };

static unsigned char hw_zero[ETH_ALEN] = { 0 };

void output_arp_frame(struct fbxbridge *br, struct net_device *dev,
		      unsigned short type,
		      unsigned long src_ip, unsigned char *src_hw,
		      unsigned long target_ip, unsigned char *target_hw)
{
	struct arphdr *arp;
	struct sk_buff *skb;
	unsigned char *arp_ptr;

	/* prepare arp packet */
	skb = dev_alloc_skb(ARP_ETHER_SIZE + dev->hard_header_len + 15);
	if (unlikely (!skb))
		return;

	skb_reserve(skb, (dev->hard_header_len + 15) & ~15);
	skb_reset_network_header(skb);
	arp = (struct arphdr *)skb_network_header(skb);
	skb_put(skb, ARP_ETHER_SIZE);

	skb->dev = dev;
	skb->protocol = htons(ETH_P_ARP);

	arp->ar_hrd = htons(dev->type);
	arp->ar_pro = htons(ETH_P_IP);
	arp->ar_hln = dev->addr_len;
	arp->ar_pln = 4;
	arp->ar_op = htons(type);

	arp_ptr = (unsigned char *)(arp + 1);

	memcpy(arp_ptr, src_hw, dev->addr_len);
	arp_ptr += dev->addr_len;
	memcpy(arp_ptr, &src_ip, 4);
	arp_ptr += 4;
	memcpy(arp_ptr, target_hw, dev->addr_len);
	arp_ptr += dev->addr_len;
	memcpy(arp_ptr, &target_ip, 4);

	/* handle promiscous mode on bridge */
	if (unlikely(br->dev->flags & IFF_PROMISC)) {
		struct sk_buff *skb2;

		if ((skb2 = skb_clone(skb, GFP_ATOMIC))) {
			skb2->dev = br->dev;
			skb2->pkt_type = PACKET_HOST;
			netif_rx(skb2);
		}
	}

	if (dev_hard_header(skb, dev, ETH_P_ARP,
			    target_hw == hw_zero ? hw_bcast : target_hw,
			    src_hw, skb->len) < 0) {
		dev_kfree_skb(skb);
		return;
	}

	dev_queue_xmit(skb);
}

void output_lan_mcast_frame(struct fbxbridge *br, struct sk_buff *skb)
{
	struct iphdr *ip;
	char mcast_hwaddr[6];
	uint32_t daddr;

	/* only send mcast if we have an active device */
	if (!br->ports[FBXBR_PORT_LAN].dev) {
		kfree(skb);
		return;
	}

	ip = ip_hdr(skb);

	/* compute mcast hwaddr */
	mcast_hwaddr[0] = 0x1;
	mcast_hwaddr[1] = 0x0;
	mcast_hwaddr[2] = 0x5e;
	daddr = ntohl(ip->daddr);
	mcast_hwaddr[3] = (daddr & 0x7f0000) >> 16;
	mcast_hwaddr[4] = (daddr & 0xff00) >> 8;
	mcast_hwaddr[5] = (daddr & 0xff);

	skb->dev = br->ports[FBXBR_PORT_LAN].dev;
	dev_hard_header(skb, skb->dev, ETH_P_802_3,
			mcast_hwaddr, skb->dev->dev_addr, ETH_P_IP);

	dev_queue_xmit(skb);
}

void output_lan_frame(struct fbxbridge *br, struct sk_buff *skb)
{
	struct iphdr *iph;

	if (!br->ports[FBXBR_PORT_LAN].dev) {
		kfree_skb(skb);
		return;
	}

	iph = ip_hdr(skb);

	if ((!br->have_hw_addr && iph->daddr != INADDR_BROADCAST)) {

		/* (fixme: try to queue instead of dropping ?) */
		kfree_skb(skb);

		/* rate limit arp sending to ARP_RATE_LIMIT  */
		if (time_before(jiffies, br->last_arp_send + ARP_RATE_LIMIT))
			return;
		br->last_arp_send = jiffies;

		output_arp_frame(br, br->ports[FBXBR_PORT_LAN].dev,
				 ARPOP_REQUEST,
				 br->wan_gw,
				 br->ports[FBXBR_PORT_LAN].dev->dev_addr,
				 br->wan_ipaddr,
				 hw_zero);
		return;
	}

	/* we have  an active device, send  to the hw addr  if we have
	 * it, or to  the bcast hw addr if we don't  or the packet is
	 * an ip broadcast */
	skb->dev = br->ports[FBXBR_PORT_LAN].dev;
	dev_hard_header(skb, skb->dev, ETH_P_802_3,
			(br->have_hw_addr &&
			 iph->daddr != INADDR_BROADCAST) ?
			br->lan_hwaddr : hw_bcast,
			skb->dev->dev_addr, ETH_P_IP);

	if (skb->fbxbridge_state == 1)
		__fbxbridge_fp_add_wan_to_lan(br, skb, br->lan_hwaddr);

	dev_queue_xmit(skb);
}

/*
 * queue the packet on the wan device
 */
void output_wan_frame(struct fbxbridge *br, struct sk_buff *skb)
{
	if (!br->ports[FBXBR_PORT_WAN].dev) {
		kfree_skb(skb);
		return;
	}

	skb->dev = br->ports[FBXBR_PORT_WAN].dev;
	if (skb->dev->type == ARPHRD_ETHER) {
		struct neighbour *n;
		struct iphdr *iph;
		__be32 nexthop;

		/*
		 * on FTTH (wan dev->type == ARPHRD_ETHER is our cue
		 * in this case) get nexthop address, if nexthop is
		 * outside local wan, it is the wan_gw.
		 */
		iph = ip_hdr(skb);
		nexthop = iph->daddr;
		if ((nexthop & br->wan_netmask) !=
		    (br->wan_ipaddr & br->wan_netmask))
				nexthop = br->wan_gw;

		/*
		 * get a neighbour, possibly creating it.
		 */
		n = __neigh_lookup(&arp_tbl, &nexthop, skb->dev, 1);
		if (!n)
			return ;

		if ((n->nud_state & NUD_VALID) == 0) {
			/*
			 * no MAC address for this neighbour (yet),
			 * trigger ARP state machine via
			 * neigh_event_send() and drop skb.
			 */

			if (net_ratelimit())
				printk("%pI4 is invalid (state 0x%x).\n",
				       &nexthop, n->nud_state);
			neigh_event_send(n, NULL);
			neigh_release(n);
			kfree_skb(skb);
			return ;
		} else
			neigh_event_send(n, NULL);

		if (skb->fbxbridge_state == 1)
			__fbxbridge_fp_add_lan_to_wan(br, skb, n->ha);

		dev_hard_header(skb, skb->dev, ETH_P_802_3, n->ha,
				skb->dev->dev_addr, ETH_P_IP);
		neigh_release(n);
	} else {
		if (skb->fbxbridge_state == 1)
			__fbxbridge_fp_add_lan_to_wan(br, skb, NULL);
	}
	dev_queue_xmit(skb);
}
