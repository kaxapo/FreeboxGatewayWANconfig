
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>

#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <linux/netfilter.h>
#include <net/netfilter/nf_conntrack.h>
#include <linux/fbxbridge.h>

#ifdef CONFIG_NETFILTER
/*
 * not available in any public header inside include/ :(
 */
unsigned int nf_iterate(struct list_head *head,
			struct sk_buff *skb,
			struct nf_hook_state *state,
			struct nf_hook_ops **elemp);

static int lolfn(struct sock *sk, struct sk_buff *skb)
{
	return 0;
}

/*
 * We can't use NF_HOOK directly here as it will kfree_skb() if it is
 * to be dropped.
 */
int fbxbridge_nf_hook(struct fbxbridge *br, uint8_t pf, unsigned int hook,
		      struct sk_buff *skb, struct net_device *in,
		      struct net_device *out)
{
	struct nf_hook_ops *elem;
	int verdict;
	struct nf_hook_state state;

	nf_hook_state_init(&state, &nf_hooks[pf][hook], hook,
			   INT_MIN, pf, in, out, skb->sk, lolfn);
	elem = list_entry_rcu(state.hook_list, struct nf_hook_ops, list);

	rcu_read_lock();
	verdict = nf_iterate(state.hook_list, skb, &state, &elem);
	rcu_read_unlock();
	return verdict;
}

/*
 * invoke netfilter FORWARD table for finer grained control
 */
static int
netfilter_lan_to_wan_packet(struct fbxbridge *br, struct sk_buff *skb)
{
	if (!br->ports[FBXBR_PORT_WAN].dev || !br->ports[FBXBR_PORT_LAN].dev)
		return NF_DROP;

	skb->nfct = &nf_ct_untracked_get()->ct_general;
	skb->nfctinfo = IP_CT_NEW;
	nf_conntrack_get(skb->nfct);

	return fbxbridge_nf_hook(br, NFPROTO_IPV4,
				 NF_INET_FORWARD, skb,
				 br->dev,
				 br->ports[FBXBR_PORT_WAN].dev);
}

/*
 * invoke netfilter FORWARD table for finer grained control
 */
static int
netfilter_wan_to_lan_packet(struct fbxbridge *br, struct sk_buff *skb)
{
	if (!br->ports[FBXBR_PORT_WAN].dev || !br->ports[FBXBR_PORT_LAN].dev)
		return NF_DROP;

	skb->nfct = &nf_ct_untracked_get()->ct_general;
	skb->nfctinfo = IP_CT_NEW;
	nf_conntrack_get(skb->nfct);

	return fbxbridge_nf_hook(br, NFPROTO_IPV4,
				 NF_INET_FORWARD, skb,
				 br->ports[FBXBR_PORT_WAN].dev,
				 br->dev);
}

#else
static inline int
netfilter_lan_to_wan_packet(struct fbxbridge *br, struct sk_buff *skb)
{ return NF_ACCEPT; }

static inline int
netfilter_wan_to_lan_packet(struct fbxbridge *br, struct sk_buff *skb)
{ return NF_ACCEPT; }
#endif


static int
filter_lan_to_wan_packet(struct fbxbridge *br, struct sk_buff *skb)
{
	struct iphdr *ip = ip_hdr(skb);

	/* disallow source spoofing */
	if (ip->saddr != br->wan_ipaddr)
		return NF_DROP;

	/* disallow all private net destination */
	if ((ntohl(ip->daddr) & 0xff000000) == 0x0a000000)
		return NF_DROP;

	if ((ntohl(ip->daddr) & 0xfff00000) == 0xac100000)
		return NF_DROP;

	if ((ntohl(ip->daddr) & 0xffff0000) == 0xc0a80000)
		return NF_DROP;

	/* no multicast please */
	if (IN_MULTICAST(ntohl(ip->daddr)))
		return NF_DROP;

	/* Don't let IP broadcast go through us */
	if (ip->daddr == INADDR_ANY)
		return NF_DROP;

	if (ip->daddr == INADDR_BROADCAST)
		return NF_DROP;

	return NF_ACCEPT;
}

/*
 * note: caller assured that ip header is valid
 */
int
fbxbridge_filter_lan_to_wan_packet(struct fbxbridge *br, struct sk_buff *skb)
{
	int ret = NF_ACCEPT;

	if ((br->flags & (FBXBRIDGE_FLAGS_FILTER))) {
		ret = filter_lan_to_wan_packet(br, skb);
		if (ret != NF_ACCEPT)
			return ret;
	}

	if ((br->flags & FBXBRIDGE_FLAGS_NETFILTER))
		ret = netfilter_lan_to_wan_packet(br, skb);

	return ret;
}

static int filter_wan_to_lan_packet(struct fbxbridge *br, struct sk_buff *skb)
{
	struct iphdr *ip = ip_hdr(skb);

	/* discard packet with obvious bad source */
	if (IN_LOOPBACK(ntohl(ip->saddr)))
		return NF_DROP;

	/* give ipv6 in ip private to freebox back to the
	 * kernel */
	if (ip->protocol == IPPROTO_IPV6) {
		struct ipv6hdr *iph6;
		unsigned int hlen;

		/* sanity check on header value */
		hlen = ip->ihl * 4;
		if (skb->len < hlen + sizeof(struct ipv6hdr))
			return NF_DROP;

		iph6 = (struct ipv6hdr *)((unsigned char *)ip + hlen);
		if ((iph6->daddr.s6_addr32[0] & htonl(0xfffffff0)) ==
		    htonl(0x2a010e30))
			return NF_STOP;
	}

	/* keep ETHER_IP packets */
	if (ip->protocol == 97)
		return NF_STOP;

	return NF_ACCEPT;
}

/*
 * note: caller assured that ip header is valid
 */
int
fbxbridge_filter_wan_to_lan_packet(struct fbxbridge *br, struct sk_buff *skb)
{
	int ret = NF_ACCEPT;

	if ((br->flags & (FBXBRIDGE_FLAGS_FILTER))) {
		ret = filter_wan_to_lan_packet(br, skb);
		if (ret != NF_ACCEPT) {
			return ret;
		}
	}

	if ((br->flags & FBXBRIDGE_FLAGS_NETFILTER))
		ret = netfilter_wan_to_lan_packet(br, skb);

	return ret;
}
