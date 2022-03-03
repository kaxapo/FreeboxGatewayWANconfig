
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/init.h>

#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/netfilter_ipv4.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <asm/checksum.h>

#include <linux/fbxbridge.h>

int fbxbridge_check_ip_packet(struct sk_buff *skb)
{
	const struct iphdr *iph;

	if (!pskb_may_pull(skb, sizeof (*iph)))
		return 1;

	iph = (struct iphdr *)skb->data;

	if (iph->ihl < 5 || iph->version != 4)
		return 1;

	if (!pskb_may_pull(skb, iph->ihl * 4))
		return 1;

	iph = (struct iphdr *)skb->data;

	if (ntohs(iph->tot_len) > skb->len)
		return 1;

	skb_reset_network_header(skb);
	skb->transport_header = skb->network_header + iph->ihl * 4;

	return 0;
}

int fbxbridge_check_udp_tcp_packet(struct sk_buff *skb)
{
	const struct iphdr *iph;

	iph = ip_hdr(skb);

	switch (iph->protocol) {
	case IPPROTO_UDP:
		if (!pskb_may_pull(skb, skb_transport_offset(skb) +
				   sizeof (struct udphdr)))
			return 1;
		break;
	case IPPROTO_TCP:
		if (!pskb_may_pull(skb, skb_transport_offset(skb) +
				   sizeof (struct tcphdr)))
			return 1;
		break;
	}
	return 0;
}

/*
 * do source or destination nat
 */
static void recalculate_checksum(struct sk_buff *skb, u32 osaddr, u32 odaddr)
{
	struct iphdr *iph;
	u16 check;

	iph = ip_hdr(skb);
	if (iph->frag_off & htons(IP_OFFSET)) {
		printk("frag => no checksum\n");
		return;
	}

	if (fbxbridge_check_udp_tcp_packet(skb))
		return;

	iph = ip_hdr(skb);

	switch (iph->protocol) {
	case IPPROTO_TCP:
	{
		struct tcphdr *tcph;

		tcph = (struct tcphdr *)skb_transport_header(skb);
		check = tcph->check;
		if (skb->ip_summed != CHECKSUM_COMPLETE)
			check = ~check;
		check = csum_tcpudp_magic(iph->saddr, iph->daddr, 0, 0, check);
		check = csum_tcpudp_magic(~osaddr, ~odaddr, 0, 0, ~check);
		if (skb->ip_summed == CHECKSUM_COMPLETE)
			check = ~check;
		tcph->check = check;
		break;
	}

	case IPPROTO_UDP:
	{
		struct udphdr *udph;

		udph = (struct udphdr *)skb_transport_header(skb);
		check = udph->check;
		if (check != 0) {
			check = csum_tcpudp_magic(iph->saddr, iph->daddr,
						  0, 0, ~check);
			check = csum_tcpudp_magic(~osaddr, ~odaddr, 0, 0,
						  ~check);
			udph->check = check ? : 0xFFFF;
		}
		break;
	}
	}
}

void fbxbridge_snat_packet(struct sk_buff *skb, unsigned long new_addr)
{
	struct iphdr	*ip;
	unsigned long	oaddr;

	ip = ip_hdr(skb);
	oaddr = ip->saddr;
	ip->saddr = new_addr;
	ip->check = 0;
	ip->check = ip_fast_csum((unsigned char *) ip, ip->ihl);
	recalculate_checksum(skb, oaddr, ip->daddr);
}

void fbxbridge_dnat_packet(struct sk_buff *skb, unsigned long new_addr)
{
	struct iphdr	*ip;
	unsigned long	oaddr;

	ip = ip_hdr(skb);
	oaddr = ip->daddr;
	ip->daddr = new_addr;
	ip->check = 0;
	ip->check = ip_fast_csum((unsigned char *) ip, ip->ihl);
	recalculate_checksum(skb, ip->saddr, oaddr);
}
