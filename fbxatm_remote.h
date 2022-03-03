#ifndef FBXATM_REMOTE_H_
#define FBXATM_REMOTE_H_

#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>

/*
 * fbxatm remote protocol messages
 */
#define ETH_P_FBXATM_REMOTE	0x8844
#define FBXATM_REMOTE_MAGIC	0xd76f8d2f

enum fbxatm_remote_flags {
	FBXATM_RFLAGS_ACK = (1 << 0),
};

enum fbxatm_remote_mtype {
	/* driver => stub */
	FBXATM_RMT_CONNECT = 0,

	/* stub => driver */
	FBXATM_RMT_DEV_LINK,
	FBXATM_RMT_DEV_RX_OAM,

	/* driver => stub */
	FBXATM_RMT_KEEPALIVE,
	FBXATM_RMT_DEV_SEND_OAM,
	FBXATM_RMT_VCC_ACTION,

	/* driver => stub */
	FBXATM_RMT_VCC_SEND,

	/* stub => driver */
	FBXATM_RMT_VCC_QEMPTY,
	FBXATM_RMT_VCC_RX,
};

struct fbxatm_remote_hdr {
	u32	magic;
	u8	flags;
	u8	seq;
	u16	len;
	u16	sport;
	u16	dport;

	u32	session_id;
	u32	mtype;
};

/*
 * sent to destination port 0
 */
struct fbxatm_remote_connect {
	u8	name[32];

	u16	dev_link_port;
	u16	dev_rx_oam_port;
};

struct fbxatm_remote_connect_ack {
	u16	vcc_action_port;
	u16	dev_send_oam_port;
	u16	keepalive_port;
	u16	pad;

	u32	max_vcc;
	u32	vci_mask;
	u32	vpi_mask;
	u32	max_priority;
	u32	max_rx_priority;

	u32	link;
	u32	link_rate_ds;
	u32	link_rate_us;
	u32	link_cell_rate_ds;
	u32	link_cell_rate_us;
};

/*
 * sent on dev_link port
 */
struct fbxatm_remote_dev_link {
	u32	link;
	u32	link_rate_ds;
	u32	link_rate_us;
	u32	link_cell_rate_ds;
	u32	link_cell_rate_us;
};

/*
 * sent on vcc_action port
 */
struct fbxatm_remote_vcc_action {
	/* 1: open - 0: close */
	u32	action;

	/*
	 * open args
	 */
	u16	vcc_rx_port;
	u16	vcc_qempty_port;

	/* from vcc id struct */
	u32	vpi;
	u32	vci;

	/* from qos struct */
	u32	traffic_class;
	u32	max_sdu;
	u32	max_buffered_pkt;
	u32	priority;
	u32	rx_priority;

	/*
	 * close args
	 */
	u32	vcc_remote_id;
};

struct fbxatm_remote_vcc_action_ack {
	u32	ret;

	/* open args ack */
	u32	vcc_remote_id;
	u16	vcc_send_port;
	u16	pad;
};

/*
 * sent on vcc_send port
 */
struct fbxatm_remote_vcc_send_ack {
	u32	full;
};

/*
 * pseudo socket layer
 */
struct fbxatm_remote_sock;
struct fbxatm_remote_ctx;

struct fbxatm_remote_sockaddr {
	u16		lport;
	u16		dport;
	u32		mtype;
	int		infinite_retry;
	int		(*deliver)(void *priv, struct sk_buff *skb,
				   struct sk_buff **ack);
	void		(*response)(void *priv, struct sk_buff *skb);
	void		*priv;
};

struct sk_buff *fbxatm_remote_alloc_skb(struct fbxatm_remote_ctx *ctx,
					unsigned int size);

unsigned int fbxatm_remote_headroom(struct fbxatm_remote_ctx *ctx);

void fbxatm_remote_sock_getaddr(struct fbxatm_remote_sock *sock,
				struct fbxatm_remote_sockaddr *addr);

void fbxatm_remote_sock_purge(struct fbxatm_remote_sock *sock);

int fbxatm_remote_sock_pending(struct fbxatm_remote_sock *sock);

struct fbxatm_remote_ctx *fbxatm_remote_alloc_ctx(struct net_device *netdev,
						  u8 *remote_mac,
						  u32 session_id,
						  void (*timeout)(void *priv),
						  void *priv);

struct fbxatm_remote_sock *
fbxatm_remote_sock_bind(struct fbxatm_remote_ctx *ctx,
			struct fbxatm_remote_sockaddr *addr,
			int send_ack);

struct fbxatm_remote_sock *
fbxatm_remote_sock_connect(struct fbxatm_remote_ctx *ctx,
			   struct fbxatm_remote_sockaddr *addr,
			   int need_ack);

int fbxatm_remote_sock_send(struct fbxatm_remote_sock *sock,
			    struct sk_buff *skb);

int fbxatm_remote_sock_send_ack(struct fbxatm_remote_sock *sock,
				struct sk_buff *skb);

int fbxatm_remote_sock_send_raw_ack(struct fbxatm_remote_ctx *ctx,
				    struct net_device *dev,
				    u8 *remote_mac,
				    struct fbxatm_remote_hdr *hdr,
				    struct sk_buff *ack);

void fbxatm_remote_sock_close(struct fbxatm_remote_sock *sock);

void fbxatm_remote_set_unknown_cb(void (*cb)(struct net_device *,
					     struct sk_buff *));

void fbxatm_remote_free_ctx(struct fbxatm_remote_ctx *ctx);

void fbxatm_remote_ctx_set_dead(struct fbxatm_remote_ctx *ctx);

int fbxatm_remote_init(void);

void fbxatm_remote_exit(void);

/*
 * platform data for fbxatm_remote driver
 */
struct fbxatm_remote_pdata {
	u8	remote_mac[ETH_ALEN];
	char	netdev_name[IFNAMSIZ];
	char	remote_name[32];
};

#endif /* !FBXATM_REMOTE_H_ */
