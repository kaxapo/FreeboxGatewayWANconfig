
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/udp.h>
#include <net/arp.h>

#include <linux/pkt_sched.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <net/ip.h>
#include <net/sock.h>
#include <net/route.h>

#include <linux/fbxbridge.h>

#ifdef CONFIG_NET_SCH_INGRESS
#include <net/pkt_sched.h>
#endif

#ifdef CONFIG_NET_CLS_ACT
static struct sk_buff *ing_filter(struct sk_buff *skb)
{
	struct tcf_proto *cl = rcu_dereference_bh(skb->dev->ingress_cl_list);
	struct tcf_result cl_res;

	/* If there's at least one ingress present somewhere (so
	 * we get here via enabled static key), remaining devices
	 * that are not configured with an ingress qdisc will bail
	 * out here.
	 */
	if (!cl)
		return skb;

	qdisc_skb_cb(skb)->pkt_len = skb->len;
	skb->tc_verd = SET_TC_AT(skb->tc_verd, AT_INGRESS);
	qdisc_bstats_update_cpu(cl->q, skb);


	switch (tc_classify(skb, cl, &cl_res)) {
	case TC_ACT_OK:
	case TC_ACT_RECLASSIFY:
		skb->tc_index = TC_H_MIN(cl_res.classid);
		break;
	case TC_ACT_SHOT:
		qdisc_qstats_drop_cpu(cl->q);
	case TC_ACT_STOLEN:
	case TC_ACT_QUEUED:
		kfree_skb(skb);
		return NULL;
	default:
		break;
	}

	return skb;
}
#endif

#ifdef CONFIG_NETFILTER
static int fbxbridge_skb_set_inputmark(struct fbxbridge *br, struct sk_buff *skb)
{
	if (skb->mark & br->inputmark) {
		if (net_ratelimit()) {
			printk(KERN_WARNING "fbxbridge: %s: input mark "
			       "already set on skb %p\n", br->name, skb);
		}
		return 0;
	}
	skb->mark |= br->inputmark;
	return 1;
}

static inline void fbxbridge_skb_clear_inputmark(struct fbxbridge *br,
						 struct sk_buff *skb)
{
	skb->mark &= ~br->inputmark;
}
#endif

static int handle_wan_frame(struct fbxbridge *br, struct sk_buff *skb)
{
	struct iphdr *iph;
	int ret;
	int verdict;

	/*
	 * filter only valid ip packet;
	 */
	if (skb->protocol != __constant_htons(ETH_P_IP))
		return NF_STOP;

	if (fbxbridge_check_ip_packet(skb)) {
		kfree_skb(skb);
		return NF_DROP;
	}

	iph = ip_hdr(skb);
	if (iph->frag_off & htons(IP_OFFSET)) {
		/* don't filter frags */
		goto done;
	}

	if (fbxbridge_check_udp_tcp_packet(skb)) {
		kfree_skb(skb);
		return NF_DROP;
	}

#ifdef CONFIG_NETFILTER
	if (br->flags & FBXBRIDGE_FLAGS_NETFILTER) {
		int changed = fbxbridge_skb_set_inputmark(br, skb);


		verdict = fbxbridge_nf_hook(br, NFPROTO_IPV4, NF_INET_LOCAL_IN,
					    skb, skb->dev, NULL);
		if (changed)
			fbxbridge_skb_clear_inputmark(br, skb);

		if (verdict == NF_ACCEPT || verdict == NF_STOP) {
			/*
			 * let it enter via the WAN interface.
			 */
			return NF_STOP;
		}
	}
#endif

	ret = fbxbridge_filter_wan_to_lan_packet(br, skb);
	if (ret != NF_ACCEPT) {
		if (ret == NF_DROP)
			kfree_skb(skb);
		return ret;
	}
	skb->fbxbridge_state = 1;

	/* don't handle packet unless wan is up */
	if (!br->wan_ipaddr) {
		kfree_skb(skb);
		return NF_DROP;
	}

done:
#ifdef CONFIG_NET_CLS_ACT
	/* pass it in ingress policer if frame is to be bridged */
	skb = ing_filter(skb);
	if (!skb)
		return NF_DROP;
	skb->tc_verd = 0;
#endif

	output_lan_frame(br, skb);
	return ret;
}

static void handle_arp_frame(struct fbxbridge *br, struct sk_buff *skb)
{
	unsigned int sender_ipaddr, target_ipaddr;
	unsigned char *sender_hwaddr, *req;
	struct arphdr *arp;

	/* sanity check on packet */
	if (skb->len < ARP_ETHER_SIZE)
		return;

	arp = (struct arphdr *)skb->data;

	if (arp->ar_hrd != __constant_htons(ARPHRD_ETHER) &&
	    arp->ar_hrd != __constant_htons(ARPHRD_IEEE802))
		return;

	if (arp->ar_pro != __constant_htons(ETH_P_IP))
		return;

	if (arp->ar_hln != ETH_ALEN)
		return;

	if (arp->ar_pln != 4)
		return;

	if (arp->ar_op != __constant_htons(ARPOP_REQUEST) &&
	    arp->ar_op != __constant_htons(ARPOP_REPLY))
		return;

	/* fetch subfields */
	req = (unsigned char *)(arp + 1);

	sender_hwaddr = req;
	req += ETH_ALEN;

	memcpy(&sender_ipaddr, req, 4);
	req += 4;

	/* skip target_hwaddr */
	req += ETH_ALEN;

	memcpy(&target_ipaddr, req, 4);

	/* ignore gratuitous ARP */
	if (!sender_ipaddr)
		return;

	if (arp->ar_op == __constant_htons(ARPOP_REQUEST)) {

		/* client is sending an arp request */
		if (!br->wan_ipaddr) {
			/* wan is down, our address is not known,
			 * answer to every arp requests */

			/* ignore what looks like gratuitous ARP */
			if (sender_ipaddr == target_ipaddr)
				return;

		} else {
			/* wan is up, filter our arp reply to match
			 * WAN */

			/* accept only arp from remote client */
			if (sender_ipaddr != br->wan_ipaddr)
				return;

			/* accept only arp request for wan network */
			if ((target_ipaddr & br->lan_netmask) !=
			    (br->wan_ipaddr & br->lan_netmask))
				return;

			/* request is for the client's address, keep quiet */
			if (target_ipaddr == br->wan_ipaddr)
				return;
		}

		/* ok I can answer */
		output_arp_frame(br, skb->dev, ARPOP_REPLY,
				 target_ipaddr,
				 skb->dev->dev_addr,
				 br->wan_ipaddr,
				 sender_hwaddr);

		/* keep the client address */
		__fbxbridge_keep_hw_addr(br, sender_hwaddr);

	} else {

		/* accept only arp from remote client */
		if (sender_ipaddr != br->wan_ipaddr)
			return;

		/* we received  an arp reply,  if it was  addressed to
		 * us, then keep the client mac address  */
		if (target_ipaddr != br->wan_gw)
			return;

		__fbxbridge_keep_hw_addr(br, sender_hwaddr);
	}
}

static inline int is_local_ip(struct fbxbridge *br, unsigned long ipaddr)
{
	int i;

	if (ipaddr == br->br_ipaddr || ipv4_is_multicast(ipaddr))
		return 1;

	for (i = 0; i < MAX_ALIASES; i++) {
		if (br->ip_aliases[i] && br->ip_aliases[i] == ipaddr)
			return 1;
	}

	return 0;
}

static int handle_lan_frame(struct fbxbridge *br, struct sk_buff *skb)
{
	struct iphdr *iph;
	int ret;

	/* handle non ip frame (arp) now */
	if (skb->protocol == __constant_htons(ETH_P_ARP)) {
		handle_arp_frame(br, skb);
		kfree_skb(skb);
		return NF_DROP;
	}

	/*
	 * filter only valid ip packet;
	 */
	if (skb->protocol != __constant_htons(ETH_P_IP))
		return NF_STOP;

	if (fbxbridge_check_ip_packet(skb)) {
		kfree_skb(skb);
		return NF_DROP;
	}

	iph = ip_hdr(skb);

	/* look  the destination  address, if  talking to  our private
	 * address or alias, then frame is local */
	if (is_local_ip(br, iph->daddr)) {
		handle_local_input_lan_frame(br, skb);
		return NF_ACCEPT;
	}

	/* don't handle packet unless wan is up */
	if (!br->wan_ipaddr) {
		kfree_skb(skb);
		return NF_DROP;
	}

	if (iph->frag_off & htons(IP_OFFSET)) {
		/* don't filter frags */
		goto done;
	}

	if (fbxbridge_check_udp_tcp_packet(skb)) {
		kfree_skb(skb);
		return NF_DROP;
	}
	iph = ip_hdr(skb);

	if ((br->flags & FBXBRIDGE_FLAGS_DHCPD) &&
	    iph->protocol == IPPROTO_UDP) {
		struct udphdr *udp;

		udp = (struct udphdr *)skb_transport_header(skb);
		if (udp->dest == htons(67)) {
			fbxbridge_dhcpd(br, skb);
			kfree_skb(skb);
			return NF_DROP;
		}
	}

	ret = fbxbridge_filter_lan_to_wan_packet(br, skb);
	if (ret != NF_ACCEPT) {
		if (ret == NF_DROP)
			kfree_skb(skb);
		return ret;
	}
	skb->fbxbridge_state = 1;

done:
	output_wan_frame(br, skb);
	return ret;
}

struct sk_buff *fbxbridge_handle_frame(struct fbxbridge *br,
				       struct sk_buff *skb)
{
	int ret;

	/* if bridge interface is down, do nothing */
	if (!(br->dev->flags & IFF_UP))
		return skb;

	/* check if frame is coming from lan or wan */
	if (skb->dev == br->ports[FBXBR_PORT_WAN].dev)
		ret = handle_wan_frame(br, skb);
	else
		ret = handle_lan_frame(br, skb);

	/* tell kernel if the packet has been consumed or not */
	return (ret != NF_STOP ? NULL : skb);
}
