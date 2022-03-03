/*
 * fbxbridge_dhcp.c
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>

#include <linux/netdevice.h>
#include <linux/udp.h>
#include <linux/netfilter.h>
#include <net/ip.h>
#include <asm/checksum.h>

#include <linux/fbxbridge.h>
#include <linux/fbxserial.h>

#define BOOTP_REQUEST   1
#define BOOTP_REPLY     2

struct bootp_pkt {              /* BOOTP packet format */
	struct iphdr iph;       /* IP header */
	struct udphdr udph;     /* UDP header */
	u8 op;                  /* 1=request, 2=reply */
	u8 htype;               /* HW address type */
	u8 hlen;                /* HW address length */
	u8 hops;                /* Used only by gateways */
	u32 xid;                /* Transaction ID */
	u16 secs;               /* Seconds since we started */
	u16 flags;              /* Just what it says */
	u32 client_ip;          /* Client's IP address if known */
	u32 your_ip;            /* Assigned IP address */
	u32 server_ip;          /* (Next, e.g. NFS) Server's IP address */
	u32 relay_ip;           /* IP address of BOOTP relay */
	u8 hw_addr[16];         /* Client's HW address */
	u8 serv_name[64];       /* Server host name */
	u8 boot_file[128];      /* Name of boot file */
	u8 exten[312];          /* DHCP options / BOOTP vendor extensions */
};


#define DHCPDISCOVER	1
#define DHCPOFFER	2
#define DHCPREQUEST	3
#define DHCPDECLINE	4
#define DHCPACK		5
#define DHCPNACK	6
#define DHCPRELEASE	7
#define DHCPINFORM	8

#define BROADCAST_FLAG	0x8000 /* "I need broadcast replies" */

static const char *dhcp_to_name[] = {
	"NONE",
	"DHCPDISCOVER",
	"DHCPOFFER",
	"DHCPREQUEST",
	"DHCPDECLINE",
	"DHCPACK",
	"DHCPNACK",
	"DHCPRELEASE",
	"DHCPINFORM",
};


#define PARAM_SUBMASK	(1 << 0)
#define PARAM_ROUTER	(1 << 1)
#define PARAM_DNS	(1 << 2)
#define PARAM_BROADCAST	(1 << 3)

struct dhcp_options
{
	u8	msg_type;
	u32	t1;		/* renewal timeout */
	u32	t2;		/* rebinding timemout */
	u32	lease_time;	/* lease time */
	u32	server_id;	/* server identifier */
	u32	request_param;	/* requested config params (bitfield) */

	u32	netmask;	/* netmask assigne to client */
	u32	router;
	u32	bcast;
	u32	dns1;
	u32	dns2;
	u32	requested_ip;

	bool	need_bcast;
};


static const unsigned char dhcp_magic_cookie[] = { 0x63, 0x82, 0x53, 0x63 };

/* parse the dhcp options string to a struct */
static void parse_dhcp_opts(const u8			*opts_str,
			    int				maxlen,
			    struct dhcp_options		*opts)
{
	const u8 *p, *end;

	memset(opts, 0, sizeof(*opts));

	/* check magic cookie */
	if (memcmp(opts_str, dhcp_magic_cookie, sizeof(dhcp_magic_cookie)))
		return;

	/* now go for options */
	p = opts_str + 4;
	end = opts_str + maxlen;

	while (p < end && *p != 0xff) {
		const u8 *option;
		size_t len, i;

		option = p++;

                if (*option == 0)
                        continue;

		/* jump of 'len' + 1 bytes */
		len = *p;
		p += len + 1;
		if (p >= end)
			break;

		/* search for known parameter */
		switch (*option) {
		case 53: /* msg_type */
			if (len)
				opts->msg_type = option[2];
			break;

		case 55: /* param request */
			for (i = 0; i < len; i++) {
				switch (option[2 + i]) {
				case 1: /* subnet */
					opts->request_param |= PARAM_SUBMASK;
					break;

				case 3: /* router */
					opts->request_param |= PARAM_ROUTER;
					break;

				case 6: /* dns */
					opts->request_param |= PARAM_DNS;
					break;

				case 28: /* broadcast */
					opts->request_param |= PARAM_BROADCAST;
					break;
				}
			}
			break;

		case 50: /* requested_ip */
			if (len >= 4)
				memcpy(&opts->requested_ip, option + 2, 4);
			break;

		case 54: /* server_id */
			if (len >= 4)
				memcpy(&opts->server_id, option + 2, 4);
			break;
}
	}
}

static void dump_dhcp_message(struct fbxbridge *br, struct sk_buff *skb,
			      struct bootp_pkt *bpkt, const char *action,
			      const char *dest)

{
	struct dhcp_options opts;

	parse_dhcp_opts(bpkt->exten, skb->len - (sizeof(*bpkt) - 312),
			&opts);

	if (opts.msg_type < 9) {
		struct iphdr *iph;

		iph = ip_hdr(skb);
		printk(KERN_DEBUG "%s: %s dhcp %s %s "
		       "(%pI4 -> %pI4) "
		       "(caddr: %pI4 - yaddr: %pI4 - "
		       "saddr: %pI4 - req_addr: %pI4)\n",
		       br->name,
		       action,
		       dhcp_to_name[opts.msg_type],
		       dest,
		       &iph->saddr,
		       &iph->daddr,
		       &bpkt->client_ip,
		       &bpkt->your_ip,
		       &bpkt->server_ip,
		       &opts.requested_ip);
	} else {
		printk(KERN_DEBUG "%s: %s unknown dhcp message %s\n",
		       br->name, action, dest);
	}
}

/* write a the dhcp options string from a struct */
static void make_dhcp_opts(u8				*opts_str,
			   const struct dhcp_options	*opts,
			   int				type)
{
	int len = 0;

	memcpy(opts_str, dhcp_magic_cookie, sizeof(dhcp_magic_cookie));
	len += sizeof(dhcp_magic_cookie);

	/* msg type (REPLY or OFFER) */
	opts_str[len++] = 53;
	opts_str[len++] = 1;
	opts_str[len++] = opts->msg_type;

	/* server id */
	opts_str[len++] = 54;
	opts_str[len++] = 4;
	memcpy(opts_str + len, &opts->server_id, 4);
	len += 4;

	/* t1 */
	if (opts->t1) {
		opts_str[len++] = 58;
		opts_str[len++] = 4;
		memcpy(opts_str + len, &opts->t1, 4);
		len += 4;
	}

	/* t2 */
	if (opts->t2) {
		opts_str[len++] = 59;
		opts_str[len++] = 4;
		memcpy(opts_str + len, &opts->t2, 4);
		len += 4;
	}

	/* lease time */
	if (opts->lease_time) {
		opts_str[len++] = 51;
		opts_str[len++] = 4;
		memcpy(opts_str + len, &opts->lease_time, 4);
		len += 4;
	}

	/* add requested_param */
	if (opts->request_param & PARAM_SUBMASK) {
		opts_str[len++] = 1;
		opts_str[len++] = 4;
		memcpy(opts_str + len, &opts->netmask, 4);
		len += 4;
	}

	if (opts->request_param & PARAM_ROUTER) {
		opts_str[len++] = 3;
		opts_str[len++] = 4;
		memcpy(opts_str + len, &opts->router, 4);
		len += 4;
	}

	if (opts->request_param & PARAM_BROADCAST) {
		opts_str[len++] = 28;
		opts_str[len++] = 4;
		memcpy(opts_str + len, &opts->bcast, 4);
		len += 4;
	}

	if (opts->request_param & PARAM_DNS) {
		opts_str[len++] = 6;
		opts_str[len++] = (opts->dns2 ? 8 : 4);
		memcpy(opts_str + len, &opts->dns1, 4);
		if (opts->dns2)
			memcpy(opts_str + len + 4, &opts->dns2, 4);
		len += (opts->dns2 ? 8 : 4);
	}

	opts_str[len++] = 255;
}

/* dhcp server */
static void send_dhcp_reply(struct fbxbridge *br, int type,
			    const struct bootp_pkt *src_packet,
			    const struct dhcp_options *src_opts)
{
	struct sk_buff		*skb;
	struct iphdr		*h;
	struct bootp_pkt	*b;
	struct dhcp_options	dhcp_opts;

	/* Allocate packet */
	skb = dev_alloc_skb(sizeof (struct bootp_pkt) + 32);
	if (!skb)
		return;

	skb_reserve(skb, 16);
	b = (struct bootp_pkt *)skb_put(skb, sizeof(struct bootp_pkt));
	memset(b, 0, sizeof(struct bootp_pkt));

	/* Construct IP header */
	skb_reset_network_header(skb);
	h = &b->iph;
	h->version = 4;
	h->ihl = 5;
	h->tot_len = htons(sizeof(struct bootp_pkt));
	h->frag_off = __constant_htons(IP_DF);
	h->ttl = 64;
	h->protocol = IPPROTO_UDP;
	h->saddr = br->wan_gw;

	switch (type) {
	case DHCPOFFER:
	case DHCPACK:
		if (src_packet->client_ip)
			h->daddr = src_packet->client_ip;
                else if (src_opts->need_bcast)
                        h->daddr = INADDR_BROADCAST;
		else
			h->daddr = br->wan_ipaddr;
		break;

	case DHCPNACK:
		/* always broadcast NAK */
		h->daddr = INADDR_BROADCAST;
		break;
	}

	h->check = ip_fast_csum((unsigned char *) h, h->ihl);

	/* Construct UDP header */
	b->udph.source = __constant_htons(67);
	b->udph.dest = __constant_htons(68);
	b->udph.len = htons(sizeof(struct bootp_pkt) - sizeof(struct iphdr));

	/* Construct DHCP header */
	b->op = BOOTP_REPLY;
	b->htype = ARPHRD_ETHER;
	b->hlen = ETH_ALEN;
	b->secs = 0;
	b->xid = src_packet->xid;

	switch (type) {
	case DHCPOFFER:
		b->server_ip = br->wan_gw;
		b->your_ip = br->wan_ipaddr;
		break;

	case DHCPACK:
		b->client_ip = src_packet->client_ip;
		b->server_ip = br->wan_gw;
		b->your_ip = br->wan_ipaddr;
		break;

	case DHCPNACK:
		break;
	}

	b->relay_ip = src_packet->relay_ip;
	memcpy(b->hw_addr, src_packet->hw_addr, sizeof(src_packet->hw_addr));

	/* Construct DHCP options */
	memset(&dhcp_opts, 0, sizeof (dhcp_opts));
	dhcp_opts.msg_type = type;
	dhcp_opts.server_id = br->wan_gw;

	switch (type) {
	case DHCPOFFER:
	case DHCPACK:
		dhcp_opts.t1 = htonl(br->dhcpd_renew_time);
		dhcp_opts.t2 = htonl(br->dhcpd_rebind_time);
		dhcp_opts.lease_time = htonl(br->dhcpd_lease_time);
		dhcp_opts.netmask = br->lan_netmask;
		dhcp_opts.bcast = (br->lan_netmask & br->wan_gw) |
			~br->lan_netmask;
		dhcp_opts.dns1 = br->dns1_ipaddr;
		dhcp_opts.dns2 = br->dns2_ipaddr ? br->dns2_ipaddr : 0;
		dhcp_opts.router = br->wan_gw;
		dhcp_opts.request_param = src_opts->request_param;
		break;
	}

	make_dhcp_opts(b->exten, &dhcp_opts, type);
	dump_dhcp_message(br, skb, b, "sending", "to lan");

	output_lan_frame(br, skb);
}

void fbxbridge_dhcpd(struct fbxbridge *br, struct sk_buff *skb)
{
	struct bootp_pkt *bpkt;
	struct dhcp_options opts;

	/* code assumes linear skb */
	if (skb_linearize(skb) < 0)
		return;

	/* reject short packet */
	if (skb->len < (sizeof(*bpkt) - 312))
		return;

	bpkt = (struct bootp_pkt *)skb->data;

	/* select only valid BOOTP Request/Discover */
	if (bpkt->op != BOOTP_REQUEST || bpkt->hlen != ETH_ALEN)
		return;

	parse_dhcp_opts(bpkt->exten, skb->len - (sizeof(*bpkt) - 312), &opts);
        if (ntohs(bpkt->flags) & BROADCAST_FLAG)
		opts.need_bcast = true;

	dump_dhcp_message(br, skb, bpkt, "received", "from lan");

	/* select DHCPDISCOVER to send a DHCPOFFER */
	if (opts.msg_type == DHCPDISCOVER) {
		__fbxbridge_keep_hw_addr(br, bpkt->hw_addr);

		send_dhcp_reply(br, DHCPOFFER, bpkt, &opts);

	} else if (opts.msg_type == DHCPREQUEST) {

		__fbxbridge_keep_hw_addr(br, bpkt->hw_addr);

		/* send ACK or NACK */
		if (!opts.requested_ip) {
			/* RENEWING/REBINDING */
			if (!bpkt->client_ip) {
				/* invalid packet; ignore */
				return;
			}

			if (bpkt->client_ip != br->wan_ipaddr)
				send_dhcp_reply(br, DHCPNACK, bpkt, &opts);
			else
				send_dhcp_reply(br, DHCPACK, bpkt, &opts);
			return;

		}

		/* INIT-REBOOT or SELECTING */
		if (bpkt->client_ip) {
			/* invalid packet; ignore */
			return;
		}

		if (!opts.server_id) {
			/* INIT-REBOOT */
			if (opts.requested_ip != br->wan_ipaddr)
				send_dhcp_reply(br, DHCPNACK, bpkt, &opts);
			else
				send_dhcp_reply(br, DHCPACK, bpkt, &opts);
			return;
		}

		/* SELECTING */
		if (opts.server_id == br->wan_gw) {
			/* client selected us */
			send_dhcp_reply(br, DHCPACK, bpkt, &opts);
		} else {
			/* ignore */
		}
	}
}
