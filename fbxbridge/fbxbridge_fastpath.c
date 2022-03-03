#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/jhash.h>
#include <linux/if_vlan.h>
#include <net/ip.h>

#include <linux/fbxbridge.h>

static inline u32 rule_hash(u32 sip, u32 dip, u16 sport, u16 dport)
{
	return jhash_3words(sip, dip, sport | dport << 16, 0);
}

static struct fbxbridge_fp_rule *
lookup_rule(const struct fbxbridge_fp *fp, u32 hash,
	    u32 sip, u32 dip, u16 sport, u16 dport)
{
	struct fbxbridge_fp_rule *r;

	hlist_for_each_entry(r, &fp->hrules[hash % FBXBR_CACHE_SIZE], hnext) {
		/* compare entry */
		if (r->sip == sip && r->dip == dip &&
		    r->sport == sport && r->dport == dport)
			return r;
	}
	return NULL;
}

static struct fbxbridge_port *get_iport_svlan(struct net_device *idev,
					      u16 vlan)
{
	struct fbxbridge *br;

	br = fbxbridge_list;
	do {
		struct fbxbridge_port *iport;

		if (!br->fast_path_enabled) {
			br = br->next;
			continue;
		}

		iport = &br->ports[FBXBR_PORT_WAN];
		if (iport->master_dev == idev &&
		    iport->vlan1 == vlan &&
		    iport->vlan2 == 0)
			return iport;

		iport = &br->ports[FBXBR_PORT_LAN];
		if (iport->master_dev == idev &&
		    iport->vlan1 == vlan &&
		    iport->vlan2 == 0)
			return iport;

		br = br->next;

	} while (br);

	return NULL;
}

static int __fp_in_ether_vlan(struct net_device *idev,
			      struct sk_buff *skb,
			      bool is_tcp)
{
	struct fbxbridge_fp_rule *rule;
	struct fbxbridge_port *iport;
	struct iphdr *iph;
	struct vlan_hdr *vhdr;
	struct fbxbridge_fp *fp;
	u16 sport, dport;
	u32 hash;

	vhdr = (struct vlan_hdr *)(skb->data + ETH_HLEN);
	iport = get_iport_svlan(idev, ntohs(vhdr->h_vlan_TCI) & VLAN_VID_MASK);
	if (!iport)
		return 0;

	skb_set_network_header(skb, VLAN_ETH_HLEN);
	iph = ip_hdr(skb);
	if (is_tcp) {
		struct tcphdr *tcph;
		tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);
		sport = tcph->source;
		dport = tcph->dest;
		fp = &iport->tcp_fp;
	} else {
		struct udphdr *udph;
		udph = (struct udphdr *)((void *)iph + iph->ihl * 4);
		sport = udph->source;
		dport = udph->dest;
		fp = &iport->udp_fp;
	}

	hash = rule_hash(iph->saddr, iph->daddr, sport, dport);
	rule = lookup_rule(fp, hash,
			   iph->saddr, iph->daddr, sport, dport);
	if (!rule)
		return 0;

	skb->fbxbridge_state = 2;
	skb->protocol = htons(ETH_P_8021Q);
	skb->dev = rule->oport->master_dev;

	memcpy(skb->data, rule->dest_hwaddr, 6);
	memcpy(skb->data + 6, skb->dev->dev_addr, 6);
	vhdr->h_vlan_TCI = htons(rule->oport->vlan1);
	dev_queue_xmit(skb);
	return 1;
}

int __fbxbridge_fp_in_vlan_tcp4(struct net_device *idev, struct sk_buff *skb)
{
	return __fp_in_ether_vlan(idev, skb, true);
}

int __fbxbridge_fp_in_vlan_udp4(struct net_device *idev, struct sk_buff *skb)
{
	return __fp_in_ether_vlan(idev, skb, false);
}

static int __fbxbridge_fp_add(struct fbxbridge *br,
			      const struct sk_buff *skb,
			      const uint8_t *new_dest_hw_addr,
			      struct fbxbridge_port *iport,
			      struct fbxbridge_port *oport)
{
	struct fbxbridge_fp_rule *rule;
	const struct iphdr *iph;
	struct fbxbridge_fp *fp;
	u32 hash;
	u16 sport, dport;

	if (!br->fast_path_enabled)
		return 0;

	iph = ip_hdr(skb);
	switch (iph->protocol) {
	case IPPROTO_UDP:
	{
		struct udphdr *udph;

		udph = (struct udphdr *)skb_transport_header(skb);
		sport = udph->source;
		dport = udph->dest;
		fp = &iport->udp_fp;
		break;
	}

	case IPPROTO_TCP:
	{
		struct tcphdr *tcph;

		tcph = (struct tcphdr *)skb_transport_header(skb);
		/* ignore unless SYN */
		if (!tcph->syn)
			return 0;
		sport = tcph->source;
		dport = tcph->dest;
		fp = &iport->tcp_fp;
		break;
	}

	default:
		return 0;
	}

	hash = rule_hash(iph->saddr, iph->daddr, sport, dport);
	rule = lookup_rule(fp, hash, iph->saddr, iph->daddr, sport, dport);
	if (rule)
		return 0;

	/* add new entry */
	if (fp->count < FBXBR_MAX_RULES) {
		rule = kmalloc(sizeof (*rule), GFP_ATOMIC);
		if (!rule)
			return 1;
		fp->count++;
	} else {
		rule = list_first_entry(&fp->rules, struct fbxbridge_fp_rule,
					next);
		hlist_del(&rule->hnext);
		list_del(&rule->next);
	}

	rule->sip = iph->saddr;
	rule->dip = iph->daddr;
	rule->sport = sport;
	rule->dport = dport;
	if (new_dest_hw_addr)
		memcpy(rule->dest_hwaddr, new_dest_hw_addr, 6);
	rule->oport = oport;
	hlist_add_head(&rule->hnext, &fp->hrules[hash % FBXBR_CACHE_SIZE]);
	list_add_tail(&rule->next, &fp->rules);

	return 0;
}

int __fbxbridge_fp_add_wan_to_lan(struct fbxbridge *br,
				  const struct sk_buff *skb,
				  const uint8_t *new_dest_hw_addr)
{
	return __fbxbridge_fp_add(br, skb, new_dest_hw_addr,
				  &br->ports[FBXBR_PORT_WAN],
				  &br->ports[FBXBR_PORT_LAN]);
}

int __fbxbridge_fp_add_lan_to_wan(struct fbxbridge *br,
				  const struct sk_buff *skb,
				  const uint8_t *new_dest_hw_addr)
{
	return __fbxbridge_fp_add(br, skb, new_dest_hw_addr,
				  &br->ports[FBXBR_PORT_LAN],
				  &br->ports[FBXBR_PORT_WAN]);
}

void fbxbridge_fp_init(struct fbxbridge *br)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(br->ports); i++) {
		struct fbxbridge_port *bport = &br->ports[i];
		size_t j;

		INIT_LIST_HEAD(&bport->tcp_fp.rules);
		for (j = 0; j < FBXBR_CACHE_SIZE; j++)
			INIT_HLIST_HEAD(&bport->tcp_fp.hrules[j]);
		bport->tcp_fp.count = 0;
		INIT_LIST_HEAD(&bport->udp_fp.rules);
		for (j = 0; j < FBXBR_CACHE_SIZE; j++)
			INIT_HLIST_HEAD(&bport->udp_fp.hrules[j]);
		bport->udp_fp.count = 0;
	}
}

static void __flush_by_dip(struct fbxbridge_fp *fp, uint32_t dip)
{
	struct fbxbridge_fp_rule *rule, *tmp;

	list_for_each_entry_safe(rule, tmp, &fp->rules, next) {
		if (rule->dip != dip)
			continue;

		hlist_del(&rule->hnext);
		list_del(&rule->next);
		kfree(rule);
		fp->count--;
	}
}

void __fbxbridge_fp_flush_by_dip(struct fbxbridge_port *bport, uint32_t dip)
{
	__flush_by_dip(&bport->tcp_fp, dip);
	__flush_by_dip(&bport->udp_fp, dip);
}

void __fbxbridge_fp_flush(struct fbxbridge *br)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(br->ports); i++) {
		struct fbxbridge_port *bport = &br->ports[i];
		struct fbxbridge_fp_rule *rule, *tmp;
		struct fbxbridge_fp *fp;

		fp = &bport->tcp_fp;
		list_for_each_entry_safe(rule, tmp, &fp->rules, next)
			kfree(rule);

		fp = &bport->udp_fp;
		list_for_each_entry_safe(rule, tmp, &fp->rules, next)
			kfree(rule);
	}
	fbxbridge_fp_init(br);
}

void fbxbridge_fp_flush_all(void)
{
	struct fbxbridge *br;

	local_bh_disable();
	br = fbxbridge_list;
	while (br) {
		if (br->fast_path_enabled)
			__fbxbridge_fp_flush(br);
		br = br->next;
	}
	local_bh_enable();
}

void __fbxbridge_fp_check(struct fbxbridge *br)
{
	struct fbxbridge_port *lport, *wport;
	bool enabled;

	lport = &br->ports[FBXBR_PORT_LAN];
	wport = &br->ports[FBXBR_PORT_WAN];

	enabled = (lport->dev && wport->dev &&
		   lport->dev->type == wport->dev->type &&
		   !(!!lport->vlan1 ^ !!wport->vlan1) &&
		   !(!!lport->vlan2 ^ !!wport->vlan2) &&
		   br->have_hw_addr &&
		   br->br_ipaddr &&
		   br->wan_ipaddr);

	if (!(enabled ^ br->fast_path_enabled)) {
		if (br->fast_path_enabled)
			__fbxbridge_fp_flush(br);
		return;
	}

	br->fast_path_enabled = enabled;
	printk(KERN_INFO "%s: fastpath is now %s\n",
	       br->name,
	       enabled ? "enabled" : "disabled");
	if (!br->fast_path_enabled)
		__fbxbridge_fp_flush(br);
}
