/*
 * "remote" driver for fbxatm, "connect" to a remote fbxatm stack in
 * net stub mode and control its PHYs
 *
 * Copyright (C) 2009 Maxime Bizon <mbizon@freebox.fr>
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/delay.h>
#include <linux/sched.h>

#include "fbxatm_remote_driver.h"

#define PFX	"fbxatm_remote_driver: "

static struct list_head remote_dev_list;
static DEFINE_SPINLOCK(remote_lock);

/*
 * request moving to dead state and schedule
 */
static void set_dying(struct driver_remote *priv)
{
	priv->want_die = 1;
	schedule_delayed_work(&priv->fsm_work, 0);
}

/*
 * socket deliver callback for vcc_rx socket
 */
static int vcc_rx_deliver(void *data, struct sk_buff *skb,
			  struct sk_buff **ack)
{
	struct driver_remote_vcc *pvcc;

	pvcc = (struct driver_remote_vcc *)data;
	fbxatm_netifrx(pvcc->vcc, skb);
	return 0;
}

/*
 * socket deliver callback for vcc_qempty socket
 */
static int vcc_qempty_deliver(void *data, struct sk_buff *skb,
			      struct sk_buff **ack)
{
	struct driver_remote_vcc *pvcc;
	struct driver_remote *priv;

	pvcc = (struct driver_remote_vcc *)data;
	priv = pvcc->priv;

	spin_lock(&priv->tx_lock);

	if (pvcc->tx_pending) {
		/* wait until we get tx ack */
		pvcc->tx_got_qempty = 1;
		goto send_ack;
	}

	/* report tx done event */
	clear_bit(FBXATM_VCC_F_FULL, &pvcc->vcc->vcc_flags);
	fbxatm_tx_done(pvcc->vcc);

send_ack:
	dev_kfree_skb(skb);
	*ack = NULL;
	spin_unlock(&priv->tx_lock);
	/* send ack now */
	return 1;
}

/*
 * socket response callback for vcc_send socket, called with bh
 * disabled
 */
static void vcc_send_response(void *data, struct sk_buff *skb)
{
	struct fbxatm_remote_vcc_send_ack *pkt_ack;
	struct driver_remote_vcc *pvcc;
	struct driver_remote *priv;

	pvcc = (struct driver_remote_vcc *)data;
	priv = pvcc->priv;

	spin_lock(&priv->tx_lock);

	if (unlikely(!pvcc->tx_pending)) {
		printk(KERN_ERR PFX "send response while no tx pending\n");
		goto out;
	}

	if (!pskb_may_pull(skb, sizeof (*pkt_ack))) {
		printk(KERN_ERR PFX "bad vcc send ack\n");
		goto out;
	}

	pvcc->tx_pending = 0;

	pkt_ack = (struct fbxatm_remote_vcc_send_ack *)skb->data;
	if (pkt_ack->full) {
		/* qempty will wake us up later, but maybe we got it
		 * already ? */
		if (!pvcc->tx_got_qempty)
			goto out;
	}

	/* wake up queue */
	clear_bit(FBXATM_VCC_F_FULL, &pvcc->vcc->vcc_flags);
	fbxatm_tx_done(pvcc->vcc);

out:
	spin_unlock(&priv->tx_lock);
	dev_kfree_skb(skb);
}

/*
 * fbxatm request to send aal5 on given vcc, called with bh disabled
 */
static int remote_send(struct fbxatm_vcc *vcc, struct sk_buff *skb)
{
	struct driver_remote_vcc *pvcc;
	struct driver_remote *priv;

	pvcc = vcc->dev_priv;
	priv = pvcc->priv;

	spin_lock(&priv->tx_lock);
	if (priv->state != RSTATE_S_ACTIVE)
		goto drop;

	if (test_bit(FBXATM_VCC_F_FULL, &vcc->vcc_flags)) {
		spin_unlock(&priv->tx_lock);
		/* return queue full */
		return 1;
	}

	if (fbxatm_remote_sock_send(pvcc->vcc_send_sock, skb)) {
		/* packet has been dropped */
		spin_unlock(&priv->tx_lock);
		return 0;
	}

	set_bit(FBXATM_VCC_F_FULL, &vcc->vcc_flags);
	pvcc->tx_pending = 1;
	pvcc->tx_got_qempty = 0;

	spin_unlock(&priv->tx_lock);
	return 0;

drop:
	spin_unlock(&priv->tx_lock);
	dev_kfree_skb(skb);
	return 0;
}

/*
 * sleep until we get an ack for sockets using wq
 */
static int __wait_ack(struct driver_remote *priv)
{
	wait_event(priv->wq, priv->wq_res != 0 ||
		   priv->state != RSTATE_S_ACTIVE);

	if (priv->wq_res == 2 || priv->state != RSTATE_S_ACTIVE) {
		/* timeout or device will die soon */
		return -EIO;
	}

	return 0;
}

/*
 * fbxatm callback to send oam cell
 */
static int remote_send_oam(struct fbxatm_dev *adev,
			   struct fbxatm_oam_cell *cell)
{
	struct driver_remote *priv;
	struct sk_buff *skb;
	int ret;

	priv = fbxatm_dev_priv(adev);
	mutex_lock(&priv->mutex);

	if (priv->state != RSTATE_S_ACTIVE) {
		mutex_unlock(&priv->mutex);
		return -ENODEV;
	}

	/* prepare outgoing packet */
	skb = fbxatm_remote_alloc_skb(priv->remote_ctx,
				      sizeof (cell->payload));
	if (!skb) {
		mutex_unlock(&priv->mutex);
		kfree(cell);
		return -ENOMEM;
	}

	memcpy(skb_put(skb, sizeof (cell->payload)), &cell->payload,
	       sizeof (cell->payload));
	kfree(cell);

	/* send & wait for ack */
	skb_queue_purge(&priv->wq_acks);
	priv->wq_res = 0;

	if (fbxatm_remote_sock_send(priv->dev_send_oam_sock, skb))
		return -ENOMEM;

	ret = __wait_ack(priv);
	mutex_unlock(&priv->mutex);

	if (ret)
		return ret;

	return 0;
}

/*
 * fbxatm callback to open given vcc
 */
static int remote_vcc_open(struct fbxatm_vcc *vcc)
{
	struct fbxatm_remote_vcc_action *pkt;
	struct fbxatm_remote_vcc_action_ack *pkt_ack;
	struct sk_buff *skb, *ack;
	struct fbxatm_remote_sockaddr addr;
	struct driver_remote_vcc *pvcc;
	struct driver_remote *priv;
	int ret;

	priv = fbxatm_dev_priv(vcc->adev);
	mutex_lock(&priv->mutex);

	if (priv->state != RSTATE_S_ACTIVE) {
		mutex_unlock(&priv->mutex);
		return -EIO;
	}

	/* allocate private vcc context */
	pvcc = kzalloc(sizeof (*pvcc), GFP_KERNEL);
	if (!pvcc) {
		mutex_unlock(&priv->mutex);
		return -ENOMEM;
	}

	pvcc->priv = priv;
	pvcc->vcc = vcc;
	vcc->dev_priv = pvcc;

	/* open input sockets */
	memset(&addr, 0, sizeof (addr));
	addr.mtype = htonl(FBXATM_RMT_VCC_RX);
	addr.priv = pvcc;
	addr.deliver = vcc_rx_deliver;
	pvcc->vcc_rx_sock = fbxatm_remote_sock_bind(priv->remote_ctx,
						    &addr, 0);
	if (!pvcc->vcc_rx_sock) {
		ret = -ENOMEM;
		goto fail;
	}

	memset(&addr, 0, sizeof (addr));
	addr.mtype = htonl(FBXATM_RMT_VCC_QEMPTY);
	addr.priv = pvcc;
	addr.deliver = vcc_qempty_deliver;
	pvcc->vcc_qempty_sock = fbxatm_remote_sock_bind(priv->remote_ctx,
							&addr, 1);
	if (!pvcc->vcc_qempty_sock) {
		ret = -ENOMEM;
		goto fail;
	}

	/* prepare outgoing packet */
	skb = fbxatm_remote_alloc_skb(priv->remote_ctx,
				      sizeof (*pkt));
	if (!skb) {
		ret = -ENOMEM;
		goto fail;
	}
	pkt = (struct fbxatm_remote_vcc_action *)skb_put(skb, sizeof (*pkt));
	pkt->action = htonl(1);

	fbxatm_remote_sock_getaddr(pvcc->vcc_rx_sock, &addr);
	pkt->vcc_rx_port = addr.lport;

	fbxatm_remote_sock_getaddr(pvcc->vcc_qempty_sock, &addr);
	pkt->vcc_qempty_port = addr.lport;

	pkt->vpi = htonl(vcc->vpi);
	pkt->vci = htonl(vcc->vci);
	pkt->traffic_class = htonl(vcc->qos.traffic_class);
	pkt->max_sdu = htonl(vcc->qos.max_sdu);
	pkt->max_buffered_pkt = htonl(vcc->qos.max_buffered_pkt);
	pkt->priority = htonl(vcc->qos.priority);
	pkt->rx_priority = htonl(vcc->qos.rx_priority);

	/* send & wait for ack */
	skb_queue_purge(&priv->wq_acks);
	priv->wq_res = 0;

	if (fbxatm_remote_sock_send(priv->vcc_action_sock, skb)) {
		ret = -ENOMEM;
		goto fail;
	}

	ret = __wait_ack(priv);

	if (ret) {
		/* timeout, device will die soon */
		goto fail;
	}

	/* check ack */
	ack = skb_dequeue(&priv->wq_acks);
	if (!pskb_may_pull(ack, sizeof (*pkt_ack))) {
		printk(KERN_ERR PFX "bad vcc action ack\n");
		dev_kfree_skb(ack);
		set_dying(priv);
		ret = -EIO;
		goto fail;
	}

	pkt_ack = (struct fbxatm_remote_vcc_action_ack *)ack->data;
	if (pkt_ack->ret) {
		printk(KERN_ERR PFX "remote vcc open failed\n");
		dev_kfree_skb(ack);
		set_dying(priv);
		ret = -EIO;
		goto fail;
	}

	pvcc->remote_id = pkt_ack->vcc_remote_id;

	memset(&addr, 0, sizeof (addr));
	addr.mtype = htonl(FBXATM_RMT_VCC_SEND);
	addr.priv = pvcc;
	addr.dport = pkt_ack->vcc_send_port;
	addr.response = vcc_send_response;
	pvcc->vcc_send_sock = fbxatm_remote_sock_connect(priv->remote_ctx,
							 &addr, 1);
	if (!pvcc->vcc_send_sock) {
		dev_kfree_skb(ack);
		set_dying(priv);
		ret = -EIO;
		goto fail;
	}

	dev_kfree_skb(ack);
	list_add(&pvcc->next, &priv->pvcc_list);
	mutex_unlock(&priv->mutex);
	return 0;

fail:
	if (pvcc->vcc_qempty_sock)
		fbxatm_remote_sock_close(pvcc->vcc_qempty_sock);
	if (pvcc->vcc_rx_sock)
		fbxatm_remote_sock_close(pvcc->vcc_rx_sock);
	kfree(pvcc);
	mutex_unlock(&priv->mutex);
	return ret;
}

/*
 * fbxatm callback to close & flush given vcc
 */
static void remote_vcc_close(struct fbxatm_vcc *vcc)
{
	struct driver_remote *priv;
	struct driver_remote_vcc *pvcc;
	struct sk_buff *skb, *ack;
	struct fbxatm_remote_vcc_action *pkt;
	struct fbxatm_remote_vcc_action_ack *pkt_ack;
	int ret;

	priv = fbxatm_dev_priv(vcc->adev);
	mutex_lock(&priv->mutex);

	pvcc = vcc->dev_priv;

	if (priv->state != RSTATE_S_ACTIVE) {
		/* just close vcc, don't tell remote */
		list_del(&pvcc->next);
		kfree(pvcc);

		/* warn fsm so it can restart */
		schedule_delayed_work(&priv->fsm_work, 0);
		goto out_unlock;
	}

	/* prepare outgoing packet */
	skb = fbxatm_remote_alloc_skb(priv->remote_ctx,
				      sizeof (*pkt));
	if (!skb) {
		set_dying(priv);
		goto out_unlock;
	}

	pkt = (struct fbxatm_remote_vcc_action *)skb_put(skb, sizeof (*pkt));
	pkt->action = htonl(0);
	pkt->vcc_remote_id = pvcc->remote_id;

	/* free vcc now, failure will trigger dead state */
	fbxatm_remote_sock_close(pvcc->vcc_send_sock);
	fbxatm_remote_sock_close(pvcc->vcc_rx_sock);
	fbxatm_remote_sock_close(pvcc->vcc_qempty_sock);
	list_del(&pvcc->next);
	kfree(pvcc);

	/* send & wait for ack */
	skb_queue_purge(&priv->wq_acks);
	priv->wq_res = 0;

	if (fbxatm_remote_sock_send(priv->vcc_action_sock, skb)) {
		set_dying(priv);
		goto out_unlock;
	}

	ret = __wait_ack(priv);

	if (ret) {
		/* timeout, device will die soon */
		mutex_unlock(&priv->mutex);
		return;
	}

	/* check ack */
	ack = skb_dequeue(&priv->wq_acks);
	if (!pskb_may_pull(ack, sizeof (*pkt_ack))) {
		printk(KERN_ERR PFX "bad vcc action close ack\n");
		dev_kfree_skb(ack);
		set_dying(priv);
		goto out_unlock;
	}

	pkt_ack = (struct fbxatm_remote_vcc_action_ack *)ack->data;
	if (pkt_ack->ret) {
		printk(KERN_ERR PFX "remote vcc close failed\n");
		dev_kfree_skb(ack);
		set_dying(priv);
		goto out_unlock;
	}

out_unlock:
	mutex_unlock(&priv->mutex);
}

/*
 * common response for vcc action & send oam socket
 */
static void common_response(void *data, struct sk_buff *skb)
{
	struct driver_remote *priv;

	priv = (struct driver_remote *)data;
	skb_queue_tail(&priv->wq_acks, skb);
	priv->wq_res = 1;
	wake_up(&priv->wq);
}

/*
 * create device procfs entries
 */
static int remote_init_procfs(struct fbxatm_dev *adev)
{
	return 0;
}

/*
 * release device procfs entries
 */
static void remote_release_procfs(struct fbxatm_dev *adev)
{
}

/*
 * local fake fbxatm device callbacks
 */
static const struct fbxatm_dev_ops remote_fbxatm_ops = {
	.open		= remote_vcc_open,
	.close		= remote_vcc_close,
	.send		= remote_send,
	.send_oam	= remote_send_oam,
	.init_procfs	= remote_init_procfs,
	.release_procfs	= remote_release_procfs,
	.owner		= THIS_MODULE,
};

/*
 * dev_rx_oam socket rx callback
 */
static int dev_rx_oam_deliver(void *data, struct sk_buff *skb,
			      struct sk_buff **ack)
{
	struct driver_remote *priv;

	priv = (struct driver_remote *)data;
	skb_queue_tail(&priv->dev_oam_reqs, skb);
	schedule_delayed_work(&priv->fsm_work, 0);

	return 0;
}

/*
 * dev_link socket rx callback
 */
static int dev_link_deliver(void *data, struct sk_buff *skb,
			    struct sk_buff **ack)
{
	struct driver_remote *priv;

	priv = (struct driver_remote *)data;
	skb_queue_tail(&priv->dev_link_reqs, skb);
	schedule_delayed_work(&priv->fsm_work, 0);

	/* send ack later */
	return 0;
}

/*
 * dev_connect socket tx ack callback
 */
static void dev_connect_response(void *data, struct sk_buff *skb)
{
	struct driver_remote *priv;

	priv = (struct driver_remote *)data;
	skb_queue_tail(&priv->connect_acks, skb);
	schedule_delayed_work(&priv->fsm_work, 0);
}

/*
 * handle link change queue
 */
static void handle_dev_link_queue(struct driver_remote *priv)
{
	struct sk_buff *skb;

	do {
		struct fbxatm_remote_dev_link *pkt;
		struct fbxatm_dev *adev;
		struct sk_buff *ack;

		skb = skb_dequeue(&priv->dev_link_reqs);
		if (!skb)
			break;

		if (!pskb_may_pull(skb, sizeof (*pkt))) {
			printk(KERN_ERR PFX "bad rx dev link\n");
			dev_kfree_skb(skb);
			continue;
		}

		pkt = (struct fbxatm_remote_dev_link *)skb->data;

		adev = priv->fbxatm_dev;
		adev->link_rate_ds = ntohl(pkt->link_rate_ds);
		adev->link_rate_us = ntohl(pkt->link_rate_us);
		adev->link_cell_rate_ds = ntohl(pkt->link_cell_rate_ds);
		adev->link_cell_rate_us = ntohl(pkt->link_cell_rate_us);

		if (pkt->link)
			fbxatm_dev_set_link_up(adev);
		else
			fbxatm_dev_set_link_down(adev);

		/* send ack */
		ack = fbxatm_remote_alloc_skb(priv->remote_ctx, 0);
		if (!ack)
			continue;
		fbxatm_remote_sock_send_ack(priv->dev_link_sock, ack);

	} while (1);
}

/*
 * handle oam rx queue
 */
static void handle_oam_rx_queue(struct driver_remote *priv)
{
	struct fbxatm_oam_cell *cell;
	struct sk_buff *skb;

	do {
		skb = skb_dequeue(&priv->dev_oam_reqs);
		if (!skb)
			break;

		cell = kmalloc(sizeof (*cell), GFP_KERNEL);
		if (!cell) {
			dev_kfree_skb(skb);
			continue;
		}

		if (!pskb_may_pull(skb, sizeof (cell->payload))) {
			printk(KERN_ERR PFX "bad rx oam\n");
			kfree(cell);
			dev_kfree_skb(skb);
			continue;
		}

		memcpy(&cell->payload, skb->data, sizeof (cell->payload));
		dev_kfree_skb(skb);
		fbxatm_netifrx_oam(priv->fbxatm_dev, cell);

	} while (1);
}

/*
 * free all and set to dead state
 */
static void remote_free(struct driver_remote *priv)
{
	struct driver_remote_vcc *pvcc;

	if (priv->state == RSTATE_S_DEAD)
		return;

	priv->want_die = 0;

	/* make sure remote_send device operation doesn't use sockets
	 * any more */
	spin_lock_bh(&priv->tx_lock);
	priv->state = RSTATE_S_DEAD;
	spin_unlock_bh(&priv->tx_lock);

	/* same goes for open_vcc, close_vcc and send_oam ops,
	 * RSTATE_S_DEAD will prevent function from being entered, and
	 * any sleeper will be woken up */
	wake_up(&priv->wq);

	mutex_lock(&priv->mutex);

	/* no vcc can be created, close all vcc sockets */
	list_for_each_entry(pvcc, &priv->pvcc_list, next) {

		if (pvcc->vcc_send_sock) {
			fbxatm_remote_sock_close(pvcc->vcc_send_sock);
			pvcc->vcc_send_sock = NULL;
		}

		if (pvcc->vcc_rx_sock) {
			fbxatm_remote_sock_close(pvcc->vcc_rx_sock);
			pvcc->vcc_rx_sock = NULL;
		}

		if (pvcc->vcc_qempty_sock) {
			fbxatm_remote_sock_close(pvcc->vcc_qempty_sock);
			pvcc->vcc_qempty_sock = NULL;
		}
	}
	mutex_unlock(&priv->mutex);

	/* no external callback from fbxatm can use sockets now */

	/* close all sockets */
	if (priv->dev_connect_sock) {
		fbxatm_remote_sock_close(priv->dev_connect_sock);
		priv->dev_connect_sock = NULL;
	}

	if (priv->keepalive_sock) {
		fbxatm_remote_sock_close(priv->keepalive_sock);
		priv->keepalive_sock = NULL;
	}

	if (priv->dev_link_sock) {
		fbxatm_remote_sock_close(priv->dev_link_sock);
		priv->dev_link_sock = NULL;
	}

	if (priv->dev_rx_oam_sock) {
		fbxatm_remote_sock_close(priv->dev_rx_oam_sock);
		priv->dev_rx_oam_sock = NULL;
	}

	if (priv->vcc_action_sock) {
		fbxatm_remote_sock_close(priv->vcc_action_sock);
		priv->vcc_action_sock = NULL;
	}

	if (priv->dev_send_oam_sock) {
		fbxatm_remote_sock_close(priv->dev_send_oam_sock);
		priv->dev_send_oam_sock = NULL;
	}

	if (priv->netdev) {
		dev_put(priv->netdev);
		priv->netdev = NULL;
	}

	if (priv->remote_ctx) {
		fbxatm_remote_free_ctx(priv->remote_ctx);
		priv->remote_ctx = NULL;
	}

	skb_queue_purge(&priv->connect_acks);
	skb_queue_purge(&priv->dev_link_reqs);
	skb_queue_purge(&priv->dev_oam_reqs);
	skb_queue_purge(&priv->wq_acks);

	if (priv->fbxatm_dev_registered) {
		fbxatm_dev_set_link_down(priv->fbxatm_dev);
		printk(KERN_WARNING "%s: marking dead\n",
		       priv->fbxatm_dev->name);
	}
}

/*
 * remote context timeout on any socket
 */
static void remote_sock_timeout(void *data)
{
	set_dying((struct driver_remote *)data);
}

/*
 * main workqueue to handle device fsm
 */
static void remote_fsm(struct work_struct *t)
{
	struct delayed_work *dwork;
	struct driver_remote *priv;
	struct net_device *netdev;
	struct fbxatm_remote_sockaddr addr;

	dwork = container_of(t, struct delayed_work, work);
	priv = container_of(dwork, struct driver_remote, fsm_work);

	if (priv->want_die) {
		remote_free(priv);
		/* let FSM restart if needed */
	}

	switch (priv->state) {
	case RSTATE_S_WAIT_NETDEV:
	{
		struct fbxatm_remote_connect *pkt;
		struct fbxatm_remote_ctx *ctx;
		struct sk_buff *skb;
		u32 session_id;

		netdev = dev_get_by_name(&init_net, priv->pd->netdev_name);
		if (!netdev) {
			/* netdev notifier will reschedule */
			return;
		}
		priv->netdev = netdev;

		/* got netdev, open remote context */
		get_random_bytes(&session_id, sizeof (session_id));
		ctx = fbxatm_remote_alloc_ctx(netdev, priv->pd->remote_mac,
					      session_id,
					      remote_sock_timeout,
					      priv);
		if (!ctx) {
			printk(KERN_ERR PFX "unable to allocate remote ctx\n");
			remote_free(priv);
			return;
		}
		priv->remote_ctx = ctx;

		/* open rx sockets */
		memset(&addr, 0, sizeof (addr));
		addr.mtype = htonl(FBXATM_RMT_DEV_LINK);
		addr.deliver = dev_link_deliver;
		addr.priv = priv;
		priv->dev_link_sock = fbxatm_remote_sock_bind(ctx, &addr, 1);
		if (!priv->dev_link_sock) {
			remote_free(priv);
			return;
		}

		memset(&addr, 0, sizeof (addr));
		addr.mtype = htonl(FBXATM_RMT_DEV_RX_OAM);
		addr.deliver = dev_rx_oam_deliver;
		addr.priv = priv;
		priv->dev_rx_oam_sock = fbxatm_remote_sock_bind(ctx, &addr, 0);
		if (!priv->dev_rx_oam_sock) {
			remote_free(priv);
			return;
		}

		/* create socket for initial connexion */
		memset(&addr, 0, sizeof (addr));
		addr.mtype = htonl(FBXATM_RMT_CONNECT);
		addr.response = dev_connect_response;
		addr.priv = priv;
		addr.infinite_retry = 1;
		priv->dev_connect_sock = fbxatm_remote_sock_connect(ctx,
								    &addr, 1);
		if (!priv->dev_connect_sock) {
			remote_free(priv);
			return;
		}

		/* send the connect packet */
		skb = fbxatm_remote_alloc_skb(priv->remote_ctx,
					      sizeof (*pkt));
		if (!skb) {
			remote_free(priv);
			return;
		}

		pkt = (struct fbxatm_remote_connect *)
			skb_put(skb, sizeof (*pkt));

		memcpy(pkt->name, priv->pd->remote_name, sizeof (pkt->name));

		fbxatm_remote_sock_getaddr(priv->dev_link_sock, &addr);
		pkt->dev_link_port = addr.lport;

		fbxatm_remote_sock_getaddr(priv->dev_rx_oam_sock, &addr);
		pkt->dev_rx_oam_port = addr.lport;

		if (fbxatm_remote_sock_send(priv->dev_connect_sock, skb)) {
			dev_kfree_skb(skb);
			remote_free(priv);
			return;
		}

		/* wait for connect ack... */
		priv->state = RSTATE_S_WAIT_REMOTE;
		break;
	}

	case RSTATE_S_WAIT_REMOTE:
	{
		struct fbxatm_remote_connect_ack *pkt_ack;
		struct fbxatm_remote_ctx *ctx;
		struct fbxatm_dev *adev;
		struct sk_buff *skb;
		int ret;

		skb = skb_dequeue(&priv->connect_acks);
		if (!skb)
			return;

		if (!pskb_may_pull(skb, sizeof (*pkt_ack))) {
			printk(KERN_ERR PFX "bad connect ack\n");
			dev_kfree_skb(skb);
			return;
		}

		pkt_ack = (struct fbxatm_remote_connect_ack *)skb->data;
		ctx = priv->remote_ctx;

		/* open sockets */
		memset(&addr, 0, sizeof (addr));
		addr.mtype = htonl(FBXATM_RMT_VCC_ACTION);
		addr.response = common_response;
		addr.dport = pkt_ack->vcc_action_port;
		addr.priv = priv;
		priv->vcc_action_sock = fbxatm_remote_sock_connect(ctx,
								   &addr, 1);
		if (!priv->vcc_action_sock) {
			remote_free(priv);
			return;
		}

		memset(&addr, 0, sizeof (addr));
		addr.mtype = htonl(FBXATM_RMT_DEV_SEND_OAM);
		addr.response = common_response;
		addr.dport = pkt_ack->dev_send_oam_port;
		addr.priv = priv;
		priv->dev_send_oam_sock = fbxatm_remote_sock_connect(ctx,
								     &addr, 1);
		if (!priv->dev_send_oam_sock) {
			remote_free(priv);
			return;
		}

		memset(&addr, 0, sizeof (addr));
		addr.mtype = htonl(FBXATM_RMT_KEEPALIVE);
		addr.priv = priv;
		addr.dport = pkt_ack->keepalive_port;
		priv->keepalive_sock = fbxatm_remote_sock_connect(ctx,
								  &addr, 1);
		if (!priv->keepalive_sock) {
			remote_free(priv);
			return;
		}

		/* all set, register fbxatm device */
		adev = priv->fbxatm_dev;
		adev->max_vcc = ntohl(pkt_ack->max_vcc);
		adev->vci_mask = ntohl(pkt_ack->vci_mask);
		adev->vpi_mask = ntohl(pkt_ack->vpi_mask);
		adev->max_priority = ntohl(pkt_ack->max_priority);
		adev->max_rx_priority = ntohl(pkt_ack->max_rx_priority);
		adev->link_rate_ds = ntohl(pkt_ack->link_rate_ds);
		adev->link_rate_us = ntohl(pkt_ack->link_rate_us);
		adev->link_cell_rate_ds = ntohl(pkt_ack->link_cell_rate_ds);
		adev->link_cell_rate_us = ntohl(pkt_ack->link_cell_rate_us);
		adev->tx_headroom = fbxatm_remote_headroom(ctx);

		/* register atm device */
		priv->state = RSTATE_S_ACTIVE;

		if (!priv->fbxatm_dev_registered) {
			ret = fbxatm_register_device(adev, "remote_fbxatm",
						     &remote_fbxatm_ops);
			if (ret) {
				remote_free(priv);
				return;
			}
		}

		priv->fbxatm_dev_registered = 1;
		printk(KERN_INFO "%s: connected to %s - %pM6/%s\n",
		       adev->name, priv->pd->remote_name,
		       priv->pd->remote_mac, priv->netdev->name);

		if (pkt_ack->link)
			fbxatm_dev_set_link_up(adev);
		else
			fbxatm_dev_set_link_down(adev);

		schedule_delayed_work(&priv->fsm_work, HZ);
		break;
	}

	case RSTATE_S_ACTIVE:
	{
		/* process link change event if any */
		handle_dev_link_queue(priv);

		/* process rx oam if any */
		handle_oam_rx_queue(priv);

		/* send keepalive */
		if (!fbxatm_remote_sock_pending(priv->keepalive_sock)) {
			struct sk_buff *skb;

			skb = fbxatm_remote_alloc_skb(priv->remote_ctx, 0);
			if (skb)
				fbxatm_remote_sock_send(priv->keepalive_sock,
							skb);
		}

		schedule_delayed_work(&priv->fsm_work, HZ);
		break;
	}

	case RSTATE_S_DEAD:
		/* wait until open vcc list is empty */
		if (!list_empty(&priv->pvcc_list))
			break;

		priv->state = RSTATE_S_WAIT_NETDEV;
		if (priv->fbxatm_dev_registered)
			printk(KERN_INFO "%s: reconnecting\n",
			       priv->fbxatm_dev->name);
		schedule_delayed_work(&priv->fsm_work, HZ);
		break;
	}
}

/*
 * netdevice notifier callback
 */
static int remote_device_event(struct notifier_block *this,
			       unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct driver_remote *priv;

	spin_lock_bh(&remote_lock);

	/* go through remote list to check if device matches one */
	list_for_each_entry(priv, &remote_dev_list, next) {

		switch (event) {
		case NETDEV_REGISTER:
			if (strcmp(dev->name, priv->pd->netdev_name))
				continue;
			break;

		case NETDEV_UNREGISTER:
			if (dev != priv->netdev)
				continue;
			priv->want_die = 1;
			break;

		default:
			continue;
		}
		schedule_delayed_work(&priv->fsm_work, 0);
	}

	spin_unlock_bh(&remote_lock);

	return 0;
}

static struct notifier_block remote_notifier = {
	.notifier_call = remote_device_event,
};

/*
 * platform data probe callback
 */
static int remote_probe(struct platform_device *pdev)
{
	struct fbxatm_remote_pdata *pd;
	struct driver_remote *priv;
	struct fbxatm_dev *adev;

	pd = pdev->dev.platform_data;
	if (!pd || !pd->netdev_name[0])
		return -EINVAL;

	/* allocate fbxatm device */
	adev = fbxatm_alloc_device(sizeof (*priv));
	if (!adev)
		return -ENOMEM;

	priv = fbxatm_dev_priv(adev);

	priv->fbxatm_dev = adev;
	INIT_LIST_HEAD(&priv->pvcc_list);
	spin_lock_init(&priv->tx_lock);
	mutex_init(&priv->mutex);

	priv->state = RSTATE_S_WAIT_NETDEV;
	INIT_DELAYED_WORK(&priv->fsm_work, remote_fsm);

	skb_queue_head_init(&priv->connect_acks);
	skb_queue_head_init(&priv->dev_link_reqs);
	skb_queue_head_init(&priv->dev_oam_reqs);
	init_waitqueue_head(&priv->wq);
	skb_queue_head_init(&priv->wq_acks);
	priv->pd = pd;

	spin_lock_bh(&remote_lock);
	list_add_tail(&priv->next, &remote_dev_list);
	spin_unlock_bh(&remote_lock);

	platform_set_drvdata(pdev, priv);

	printk(KERN_INFO PFX "connecting to %s - %pM6/%s\n",
	       priv->pd->remote_name,
	       priv->pd->remote_mac,
	       priv->pd->netdev_name);

	/* kick fsm  */
	schedule_delayed_work(&priv->fsm_work, 0);
	return 0;
}

static int remote_remove(struct platform_device *pdev)
{
	struct driver_remote *priv;
	struct fbxatm_dev *adev;

	priv = platform_get_drvdata(pdev);
	adev = priv->fbxatm_dev;

	/* remove from global list so network notifier can't find us */
	spin_lock_bh(&remote_lock);
	list_del(&priv->next);
	spin_unlock_bh(&remote_lock);

	/* cancel any pending fsm */
	cancel_delayed_work_sync(&priv->fsm_work);

	/* force dead state */
	remote_free(priv);

	if (priv->fbxatm_dev_registered)
		fbxatm_unregister_device(adev);
	fbxatm_free_device(adev);
	return 0;
}

struct platform_driver fbxatm_remote_driver = {
	.probe	= remote_probe,
	.remove	= remote_remove,
	.driver	= {
		.name	= "fbxatm_remote",
		.owner  = THIS_MODULE,
	},
};

static int __init fbxatm_remote_driver_init(void)
{
	int ret;

	INIT_LIST_HEAD(&remote_dev_list);
	ret = fbxatm_remote_init();
	if (ret)
		goto fail;
	ret = register_netdevice_notifier(&remote_notifier);
	if (ret)
		goto fail_remote;
	ret = platform_driver_register(&fbxatm_remote_driver);
	if (ret)
		goto fail_notifier;
	return 0;

fail_notifier:
	unregister_netdevice_notifier(&remote_notifier);
fail_remote:
	fbxatm_remote_exit();
fail:
	return ret;
}

static void __exit fbxatm_remote_driver_exit(void)
{
	fbxatm_remote_exit();
	unregister_netdevice_notifier(&remote_notifier);
	platform_driver_unregister(&fbxatm_remote_driver);
}

module_init(fbxatm_remote_driver_init);
module_exit(fbxatm_remote_driver_exit);

MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");
MODULE_AUTHOR("Maxime Bizon <mbizon@freebox.fr>");
