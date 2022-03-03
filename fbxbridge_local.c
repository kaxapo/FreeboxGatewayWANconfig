
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/pkt_sched.h>

#include <linux/ip.h>

#include <linux/fbxbridge.h>

void handle_local_input_lan_frame(struct fbxbridge *br, struct sk_buff *skb)
{
	if (!br->br_remote_ipaddr) {
		kfree_skb(skb);
		return;
	}

	/* packet comes from lan, snat it and make it local */
	fbxbridge_snat_packet(skb, br->br_remote_ipaddr);
	skb->dev = br->dev;
	skb->pkt_type = PACKET_HOST;
	br->dev->stats.rx_packets++;
	br->dev->stats.rx_bytes += skb->len;
	netif_rx(skb);
}

int handle_local_output_frame(struct fbxbridge *br, struct sk_buff *skb)
{
	struct iphdr *ip;

	/* if no wan addr, we can't do anything */
	if (!br->wan_ipaddr) {
		kfree_skb(skb);
		return 1;
	}

	/*
	 * filter only valid packets
	 */
	if (skb->protocol != __constant_htons(ETH_P_IP)) {
		kfree_skb(skb);
		return 1;
	}

        if (fbxbridge_check_ip_packet(skb)) {
                kfree_skb(skb);
                return 1;
	}
	ip = ip_hdr(skb);

	if (ipv4_is_multicast(ip->daddr)) {
		output_lan_mcast_frame(br, skb);
		return 0;
	}

	if (ip->daddr != br->br_remote_ipaddr) {
		kfree_skb(skb);
		return 1;
	}

	fbxbridge_dnat_packet(skb, br->wan_ipaddr);
	output_lan_frame(br, skb);
	return 0;
}
