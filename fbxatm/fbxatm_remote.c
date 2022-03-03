#include <linux/module.h>
#include <linux/fbxatm.h>
#include <linux/fbxatm_dev.h>
#include <linux/fbxatm_remote.h>
#include <asm/unaligned.h>

#define PFX		"fbxatm_remote: "
#define MAX_PORTS	64
#define MAX_RETRANS	10
#define RETRANS_TIMER	(HZ / 3)

struct fbxatm_remote_ctx;

struct fbxatm_remote_sock {
	spinlock_t			lock;
	struct fbxatm_remote_sockaddr	addr;

	struct timer_list		retrans_timer;
	unsigned int			retrans_count;

	struct sk_buff			*pending;

	/* 1 for output */
	int				direction;

	/* wait ack for output, send ack for input */
	int				has_ack;

	u8				seq;

	struct fbxatm_remote_ctx	*ctx;
	struct list_head		next;
};

struct fbxatm_remote_ctx {
	spinlock_t			lock;
	int				dead;

	struct net_device		*netdev;
	u8				remote_mac[ETH_ALEN];
	u32				session_id;

	struct fbxatm_remote_sock	*socks_per_lport[MAX_PORTS];
	struct sk_buff			*pending_zero_ack;

	void				(*timeout_cb)(void *priv);
	void				*priv;

	struct list_head		next;
};

static struct list_head ctx_list;
static DEFINE_SPINLOCK(ctx_list_lock);
static void (*unknown_cb)(struct net_device *,
			  struct sk_buff *);

unsigned int fbxatm_remote_headroom(struct fbxatm_remote_ctx *ctx)
{
	return sizeof (struct fbxatm_remote_hdr) +
		ctx->netdev->hard_header_len + ctx->netdev->needed_headroom;
}

EXPORT_SYMBOL(fbxatm_remote_headroom);

/*
 * allocate skb with enough headroom for header
 */
struct sk_buff *fbxatm_remote_alloc_skb(struct fbxatm_remote_ctx *ctx,
					unsigned int size)
{
	struct sk_buff *skb;
	unsigned int hroom_size;

	hroom_size = fbxatm_remote_headroom(ctx);
	skb = dev_alloc_skb(hroom_size + size);
	if (!skb)
		return NULL;
	skb_reserve(skb, hroom_size);
	return skb;
}

EXPORT_SYMBOL(fbxatm_remote_alloc_skb);

/*
 * return sock addr
 */
void fbxatm_remote_sock_getaddr(struct fbxatm_remote_sock *sock,
				struct fbxatm_remote_sockaddr *addr)
{
	memcpy(addr, &sock->addr, sizeof (*addr));
}

EXPORT_SYMBOL(fbxatm_remote_sock_getaddr);

/*
 * socket retrans timer callback
 */
static void sock_timer(unsigned long data)
{
	struct fbxatm_remote_sock *sock;
	struct sk_buff *skb;

	sock = (struct fbxatm_remote_sock *)data;

	spin_lock_bh(&sock->ctx->lock);
	spin_lock(&sock->lock);

	if (!sock->addr.infinite_retry && sock->retrans_count >= MAX_RETRANS) {
		printk(KERN_ERR PFX "retrans max reached\n");
		sock->ctx->dead = 1;
		dev_kfree_skb(sock->pending);
		sock->pending = NULL;
		if (sock->ctx->timeout_cb)
			sock->ctx->timeout_cb(sock->ctx->priv);
		spin_unlock(&sock->lock);
		spin_unlock_bh(&sock->ctx->lock);
		return;
	}

	sock->retrans_count++;
	sock->retrans_timer.expires = jiffies + RETRANS_TIMER;

	skb = skb_clone(sock->pending, GFP_ATOMIC);
	if (skb)
		dev_queue_xmit(skb);
	add_timer(&sock->retrans_timer);

	spin_unlock(&sock->lock);
	spin_unlock_bh(&sock->ctx->lock);
}

/*
 * append header for given socket
 */
static int append_tx_header(struct fbxatm_remote_sock *sock,
			    struct sk_buff *skb)
{
	struct fbxatm_remote_hdr *hdr;
	unsigned int needed;

	needed = skb->dev->hard_header_len + skb->dev->needed_headroom +
		sizeof (*hdr);

	if (unlikely(skb_headroom(skb) < needed)) {
		if (net_ratelimit())
			printk(KERN_WARNING PFX "headroom too small %d < %d\n",
			       skb_headroom(skb), needed);
	}

	if (skb_cow_head(skb, needed))
		return 1;

	hdr = (struct fbxatm_remote_hdr *)skb_push(skb, sizeof (*hdr));
	skb_set_network_header(skb, 0);

	put_unaligned(htonl(FBXATM_REMOTE_MAGIC), &hdr->magic);
	if (sock->direction == 1) {
		/* output */
		hdr->flags = 0;
	} else {
		/* input */
		hdr->flags = FBXATM_RFLAGS_ACK;
	}
	hdr->seq = sock->seq;
	put_unaligned(htons(skb->len), &hdr->len);
	put_unaligned(sock->addr.lport, &hdr->sport);
	put_unaligned(sock->addr.dport, &hdr->dport);

	put_unaligned(sock->addr.mtype, &hdr->mtype);
	put_unaligned(sock->ctx->session_id, &hdr->session_id);

	skb->protocol = htons(ETH_P_FBXATM_REMOTE);
	if (dev_hard_header(skb, skb->dev, ETH_P_FBXATM_REMOTE,
			    sock->ctx->remote_mac, NULL, skb->len) < 0)
		return 1;

	return 0;
}

/*
 * purge socket send queue, advance next sequence
 */
void fbxatm_remote_sock_purge(struct fbxatm_remote_sock *sock)
{
	spin_lock_bh(&sock->lock);
	if (sock->pending) {
		del_timer_sync(&sock->retrans_timer);
		dev_kfree_skb(sock->pending);
		sock->pending = NULL;
		sock->seq++;
	}
	spin_unlock_bh(&sock->lock);
}

EXPORT_SYMBOL(fbxatm_remote_sock_purge);

/*
 * check if tx is pending on socket
 */
int fbxatm_remote_sock_pending(struct fbxatm_remote_sock *sock)
{
	int ret;

	spin_lock_bh(&sock->lock);
	ret = sock->pending ? 1 : 0;
	spin_unlock_bh(&sock->lock);
	return ret;
}

EXPORT_SYMBOL(fbxatm_remote_sock_pending);

/*
 * send skb on socket
 */
int fbxatm_remote_sock_send(struct fbxatm_remote_sock *sock,
			    struct sk_buff *skb)
{
	BUG_ON(sock->direction == 0);

	spin_lock_bh(&sock->lock);
	skb->dev = sock->ctx->netdev;

	if (append_tx_header(sock, skb)) {
		spin_unlock_bh(&sock->lock);
		dev_kfree_skb(skb);
		return 1;
	}

	if (unlikely(sock->ctx->dead)) {
		spin_unlock_bh(&sock->lock);
		dev_kfree_skb(skb);
		return 0;
	}

	/* start retrans timer if needed */
	if (sock->has_ack) {
		if (sock->pending) {
			printk(KERN_ERR PFX "sock already has tx pending\n");
			spin_unlock_bh(&sock->lock);
			dev_kfree_skb(skb);
			return 1;
		}

		sock->pending = skb_clone(skb, GFP_ATOMIC);
		if (sock->pending) {
			sock->retrans_count = 0;
			sock->retrans_timer.expires = jiffies + RETRANS_TIMER;
			add_timer(&sock->retrans_timer);
		}
	}

	spin_unlock_bh(&sock->lock);
	dev_queue_xmit(skb);

	return 0;
}

EXPORT_SYMBOL(fbxatm_remote_sock_send);

/*
 * send ack skb on socket
 */
int fbxatm_remote_sock_send_ack(struct fbxatm_remote_sock *sock,
				struct sk_buff *skb)
{
	BUG_ON(sock->direction == 1);

	spin_lock_bh(&sock->lock);

	skb->dev = sock->ctx->netdev;

	if (append_tx_header(sock, skb)) {
		spin_unlock_bh(&sock->lock);
		dev_kfree_skb(skb);
		return 1;
	}

	if (unlikely(sock->ctx->dead)) {
		spin_unlock_bh(&sock->lock);
		dev_kfree_skb(skb);
		return 0;
	}

	skb->dev = sock->ctx->netdev;
	sock->pending = skb_clone(skb, GFP_ATOMIC);
	spin_unlock_bh(&sock->lock);
	dev_queue_xmit(skb);

	return 0;
}

EXPORT_SYMBOL(fbxatm_remote_sock_send_ack);

/*
 * send raw ack
 */
int fbxatm_remote_sock_send_raw_ack(struct fbxatm_remote_ctx *ctx,
				    struct net_device *dev,
				    u8 *remote_mac,
				    struct fbxatm_remote_hdr *hdr,
				    struct sk_buff *ack)
{
	struct fbxatm_remote_hdr *ack_hdr;

	if (skb_cow_head(ack, sizeof (*ack_hdr))) {
		dev_kfree_skb(ack);
		return 1;
	}

	ack_hdr = (struct fbxatm_remote_hdr *)skb_push(ack, sizeof (*hdr));
	skb_set_network_header(ack, 0);

	put_unaligned(htonl(FBXATM_REMOTE_MAGIC), &ack_hdr->magic);
	ack_hdr->flags = FBXATM_RFLAGS_ACK;
	ack_hdr->seq = hdr->seq;

	put_unaligned(htons(ack->len), &ack_hdr->len);
	put_unaligned(hdr->dport, &ack_hdr->sport);
	put_unaligned(hdr->sport, &ack_hdr->dport);
	put_unaligned(hdr->mtype, &ack_hdr->mtype);
	put_unaligned(hdr->session_id, &ack_hdr->session_id);

	ack->dev = dev;

	if (dev_hard_header(ack, dev, ETH_P_FBXATM_REMOTE,
			    remote_mac, NULL, ack->len) < 0) {
		dev_kfree_skb(ack);
		return 1;
	}

	if (hdr->dport == 0) {
		kfree(ctx->pending_zero_ack);
		ctx->pending_zero_ack = skb_clone(ack, GFP_ATOMIC);
	}

	if (dev_queue_xmit(ack))
		return 1;

	return 0;
}

EXPORT_SYMBOL(fbxatm_remote_sock_send_raw_ack);

/*
 * handle input data on 'in' direction socket
 */
static void __in_sock_rcv(struct fbxatm_remote_sock *sock,
			  struct sk_buff *skb,
			  struct fbxatm_remote_hdr *hdr)
{
	struct sk_buff *ack;
	int ret;

	spin_lock(&sock->lock);

	if (sock->has_ack) {
		u8 expected_seq;

		/* check for duplicate seq  */
		if (hdr->seq == sock->seq) {

			/* got last packet again, ack has been
			 * lost, send it again if we have it */
			if (sock->pending) {
				ack = skb_clone(sock->pending, GFP_ATOMIC);
				if (ack)
					dev_queue_xmit(ack);
			}

			spin_unlock(&sock->lock);
			dev_kfree_skb(skb);
			return;
		}

		expected_seq = sock->seq + 1;
		if (hdr->seq != expected_seq) {
			/* lost sync */
			spin_unlock(&sock->lock);
			dev_kfree_skb(skb);
			return;
		}

		/* about to accept new packet, free any pending ack */
		dev_kfree_skb(sock->pending);
		sock->pending = NULL;

		sock->seq = hdr->seq;

		/* set sock dport to last receive packet to send
		 * correct ack */
		sock->addr.dport = hdr->sport;
	}

	/* deliver packet to socket */
	ret = sock->addr.deliver(sock->addr.priv, skb, &ack);

	if (!sock->has_ack || !ret) {
		/* don't send ack now */
		spin_unlock(&sock->lock);
		return;
	}

	if (!ack) {
		/* generate empty ack */
		ack = fbxatm_remote_alloc_skb(sock->ctx, 0);
		if (!ack) {
			spin_unlock(&sock->lock);
			return;
		}
	}

	ack->dev = sock->ctx->netdev;

	if (append_tx_header(sock, ack)) {
		spin_unlock(&sock->lock);
		dev_kfree_skb(ack);
		return;
	}

	sock->pending = ack;

	/* send ack now */
	ack = skb_clone(sock->pending, GFP_ATOMIC);
	spin_unlock(&sock->lock);

	if (ack)
		dev_queue_xmit(ack);
}

/*
 * handle data on 'out' direction socket
 */
static void __out_sock_rcv(struct fbxatm_remote_sock *sock,
			   struct sk_buff *skb,
			   struct fbxatm_remote_hdr *hdr)
{
	if (!sock->has_ack) {
		dev_kfree_skb(skb);
		printk(KERN_ERR PFX "ack for non ack sock\n");
		return;
	}

	spin_lock(&sock->lock);

	/* check if ack if for last sent seq */
	if (hdr->seq != sock->seq) {
		spin_unlock(&sock->lock);
		dev_kfree_skb(skb);
		return;
	}

	/* make sure we're expecting it */
	if (!sock->pending) {
		spin_unlock(&sock->lock);
		dev_kfree_skb(skb);
		return;
	}

	del_timer_sync(&sock->retrans_timer);
	dev_kfree_skb(sock->pending);
	sock->pending = NULL;
	sock->seq++;

	if (sock->addr.response)
		sock->addr.response(sock->addr.priv, skb);
	else
		dev_kfree_skb(skb);

	spin_unlock(&sock->lock);
}

/*
 * fbxatm ethertype rx callback
 */
static int fbxatm_rcv(struct sk_buff *skb, struct net_device *dev,
		      struct packet_type *pt, struct net_device *orig_dev)
{
	struct fbxatm_remote_hdr *hdr;
	struct fbxatm_remote_ctx *ctx;
	int found;
	unsigned int len;
	u16 port;

	if (!netif_running(dev)) {
		dev_kfree_skb(skb);
		return 0;
	}

	skb = skb_unshare(skb, GFP_ATOMIC);
	if (!skb)
		return 0;

	/* decode fbxatm ethertype */
	if (!pskb_may_pull(skb, sizeof (*hdr))) {
		dev_kfree_skb(skb);
		return 0;
	}

	hdr = (struct fbxatm_remote_hdr *)skb_network_header(skb);
	if (ntohl(hdr->magic) != FBXATM_REMOTE_MAGIC) {
		if (net_ratelimit())
			printk(KERN_ERR PFX "bad fbxatm remote magic: %08x\n",
			       ntohl(hdr->magic));
		dev_kfree_skb(skb);
		return 0;
	}

	/* check len */
	len = ntohs(hdr->len);
	if (skb->len < len) {
		if (net_ratelimit())
			printk(KERN_ERR PFX "short packet\n");
		dev_kfree_skb(skb);
		return 0;
	}

	/* trim skb to correct size */
	if (pskb_trim(skb, len)) {
		dev_kfree_skb(skb);
		return 0;
	}

	port = ntohs(hdr->dport);
	if (port >= MAX_PORTS) {
		dev_kfree_skb(skb);
		printk(KERN_ERR PFX "bad port %u\n", port);
		return 0;
	}

	/* remove header */
	skb_set_network_header(skb, 0);
	__skb_pull(skb, sizeof (*hdr));
	skb_set_transport_header(skb, 0);

	/* find context by mac/session id */
	found = 0;
	spin_lock_bh(&ctx_list_lock);
	list_for_each_entry(ctx, &ctx_list, next) {
		struct ethhdr *eth;
		struct fbxatm_remote_sock *sock;
		int is_ack;

		eth = eth_hdr(skb);
		if (memcmp(eth->h_source, ctx->remote_mac, ETH_ALEN))
			continue;

		if (hdr->session_id != ctx->session_id)
			continue;

		spin_lock(&ctx->lock);

		if (unlikely(ctx->dead)) {
			spin_unlock(&ctx->lock);
			continue;
		}

		/* found context, find socket by port */
		found = 1;

		/* special case for port 0, in case ack is lost */
		if (port == 0 && ctx->pending_zero_ack) {
			struct sk_buff *ack;
			ack = skb_clone(ctx->pending_zero_ack, GFP_ATOMIC);
			if (ack)
				dev_queue_xmit(ack);
			spin_unlock(&ctx->lock);
			break;
		}

		sock = ctx->socks_per_lport[port];
		if (!sock) {
			printk(KERN_ERR PFX "context but no socket for "
			       "port: %u\n", port);
			spin_unlock(&ctx->lock);
			break;
		}

		if (hdr->mtype != sock->addr.mtype) {
			printk(KERN_ERR PFX "incorrect mtype for sock\n");
			spin_unlock(&ctx->lock);
			break;
		}

		/* check direction, we should only get ack for output
		 * socket */
		is_ack = (hdr->flags & FBXATM_RFLAGS_ACK) ? 1 : 0;
		if (sock->direction ^ is_ack) {
			printk(KERN_ERR PFX "incorrect ack value for sock\n");
			spin_unlock(&ctx->lock);
			break;
		}

		/* ok deliver */
		if (sock->direction)
			__out_sock_rcv(sock, skb, hdr);
		else
			__in_sock_rcv(sock, skb, hdr);

		spin_unlock(&ctx->lock);
		spin_unlock_bh(&ctx_list_lock);
		return 0;
	}

	spin_unlock_bh(&ctx_list_lock);

	if (!found && unknown_cb)
		unknown_cb(dev, skb);
	else
		dev_kfree_skb(skb);

	return 0;
}

void fbxatm_remote_set_unknown_cb(void (*cb)(struct net_device *,
					     struct sk_buff *))
{
	unknown_cb = cb;
}

EXPORT_SYMBOL(fbxatm_remote_set_unknown_cb);

/*
 * allocate local port for socket
 */
static int __alloc_lport(struct fbxatm_remote_ctx *ctx,
			 struct fbxatm_remote_sock *sock)
{
	int i;

	for (i = 1; i < ARRAY_SIZE(ctx->socks_per_lport); i++) {
		if (ctx->socks_per_lport[i])
			continue;
		sock->addr.lport = htons(i);
		ctx->socks_per_lport[i] = sock;
		return 0;
	}
	return -EADDRINUSE;
}

static struct fbxatm_remote_sock *sock_new(struct fbxatm_remote_sockaddr *addr)
{
	struct fbxatm_remote_sock *sock;

	sock = kzalloc(sizeof (*sock), GFP_KERNEL);
	if (!sock)
		return NULL;
	memcpy(&sock->addr, addr, sizeof (*addr));
	init_timer(&sock->retrans_timer);
	spin_lock_init(&sock->lock);
	sock->retrans_timer.data = (unsigned long)sock;
	sock->retrans_timer.function = sock_timer;
	return sock;
}

struct fbxatm_remote_sock *
fbxatm_remote_sock_connect(struct fbxatm_remote_ctx *ctx,
			   struct fbxatm_remote_sockaddr *addr,
			   int need_ack)
{
	struct fbxatm_remote_sock *sock;

	sock = sock_new(addr);
	if (!sock)
		return NULL;

	spin_lock_bh(&ctx->lock);
	sock->ctx = ctx;
	if (__alloc_lport(ctx, sock)) {
		spin_unlock_bh(&ctx->lock);
		kfree(sock);
		return NULL;
	}

	sock->direction = 1;
	sock->seq = 0;
	sock->has_ack = need_ack;
	spin_unlock_bh(&ctx->lock);

	return sock;
}

EXPORT_SYMBOL(fbxatm_remote_sock_connect);

struct fbxatm_remote_sock *
fbxatm_remote_sock_bind(struct fbxatm_remote_ctx *ctx,
			struct fbxatm_remote_sockaddr *addr,
			int send_ack)
{
	struct fbxatm_remote_sock *sock;

	sock = sock_new(addr);
	if (!sock)
		return NULL;

	spin_lock_bh(&ctx->lock);
	sock->ctx = ctx;
	if (__alloc_lport(ctx, sock)) {
		spin_unlock_bh(&ctx->lock);
		kfree(sock);
		return NULL;
	}

	sock->direction = 0;
	sock->seq = ~0;
	sock->has_ack = send_ack;
	spin_unlock_bh(&ctx->lock);

	return sock;
}

EXPORT_SYMBOL(fbxatm_remote_sock_bind);

void fbxatm_remote_sock_close(struct fbxatm_remote_sock *sock)
{
	spin_lock_bh(&sock->ctx->lock);
	if (sock->addr.lport)
		sock->ctx->socks_per_lport[ntohs(sock->addr.lport)] = NULL;

	spin_lock(&sock->lock);
	del_timer_sync(&sock->retrans_timer);
	dev_kfree_skb(sock->pending);
	spin_unlock(&sock->lock);
	spin_unlock_bh(&sock->ctx->lock);
	kfree(sock);
}

EXPORT_SYMBOL(fbxatm_remote_sock_close);

struct fbxatm_remote_ctx *fbxatm_remote_alloc_ctx(struct net_device *netdev,
						  u8 *remote_mac,
						  u32 session_id,
						  void (*timeout)(void *priv),
						  void *priv)
{
	struct fbxatm_remote_ctx *ctx;

	ctx = kzalloc(sizeof (*ctx), GFP_KERNEL);
	if (!ctx)
		return NULL;
	ctx->netdev = netdev;
	spin_lock_init(&ctx->lock);
	memcpy(ctx->remote_mac, remote_mac, ETH_ALEN);
	ctx->session_id = session_id;
	ctx->timeout_cb = timeout;
	ctx->priv = priv;

	spin_lock_bh(&ctx_list_lock);
	list_add_tail(&ctx->next, &ctx_list);
	spin_unlock_bh(&ctx_list_lock);

	return ctx;
}

EXPORT_SYMBOL(fbxatm_remote_alloc_ctx);

void fbxatm_remote_ctx_set_dead(struct fbxatm_remote_ctx *ctx)
{
	spin_lock_bh(&ctx->lock);
	ctx->dead = 1;
	spin_unlock_bh(&ctx->lock);
}

EXPORT_SYMBOL(fbxatm_remote_ctx_set_dead);

void fbxatm_remote_free_ctx(struct fbxatm_remote_ctx *ctx)
{
	int i;

	spin_lock_bh(&ctx_list_lock);
	spin_lock(&ctx->lock);

	for (i = 1; i < ARRAY_SIZE(ctx->socks_per_lport); i++) {
		if (!ctx->socks_per_lport[i])
			continue;
		printk(KERN_ERR PFX "socket count is not 0\n");
		spin_unlock(&ctx->lock);
		spin_unlock_bh(&ctx_list_lock);
		return;
	}

	kfree(ctx->pending_zero_ack);
	list_del(&ctx->next);
	spin_unlock(&ctx->lock);
	spin_unlock_bh(&ctx_list_lock);
	kfree(ctx);
}

EXPORT_SYMBOL(fbxatm_remote_free_ctx);

static struct packet_type fbxatm_packet_type = {
	.type	= __constant_htons(ETH_P_FBXATM_REMOTE),
	.func	= fbxatm_rcv,
};

int fbxatm_remote_init(void)
{
	spin_lock_init(&ctx_list_lock);
	INIT_LIST_HEAD(&ctx_list);
	dev_add_pack(&fbxatm_packet_type);
	return 0;
}

EXPORT_SYMBOL(fbxatm_remote_init);

void fbxatm_remote_exit(void)
{
	dev_remove_pack(&fbxatm_packet_type);
}

EXPORT_SYMBOL(fbxatm_remote_exit);
