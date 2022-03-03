#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/if_pppox.h>
#include <linux/ppp_channel.h>
#include <linux/ppp_defs.h>
#include <linux/if_ppp.h>
#include <linux/fbxatm.h>
#include <linux/fbxatm_dev.h>
#include "fbxatm_priv.h"

#define PFX	"fbxatm_pppoa: "

static LIST_HEAD(fbxatm_pppoa_vcc_list);
static DEFINE_MUTEX(fbxatm_pppoa_mutex);

/*
 * private data for pppoa vcc
 */
struct fbxatm_pppoa_vcc {
	struct fbxatm_vcc		*vcc;
	struct fbxatm_pppoa_vcc_params	params;
	enum fbxatm_pppoa_encap		cur_encap;

	/* used by ppp */
	int				flags;
	struct ppp_channel		chan;

	struct socket			*sock;
	struct list_head		next;
};


#define __LLC_HDR		0xfe, 0xfe, 0x03
#define __NLPID_PPP		0xcf
#define __PPP_LCP		0xc0, 0x21

static const u8 llc_ppp[]	= { __LLC_HDR, __NLPID_PPP };
static const u8 llc_ppp_lcp[]	= { __LLC_HDR, __NLPID_PPP, __PPP_LCP };
static const u8 lcp[]		= { __PPP_LCP };


/*
 * fbxatm stack receive callback, called from softirq
 */
static void vcc_rx_callback(struct sk_buff *skb, void *data)
{
	struct fbxatm_pppoa_vcc *priv;

	priv = (struct fbxatm_pppoa_vcc *)data;

	if (priv->chan.ppp == NULL) {
		dev_kfree_skb(skb);
		return;
	}

	switch (priv->cur_encap) {
	case FBXATM_EPPPOA_VCMUX:
		/* nothing to do */
		break;

	case FBXATM_EPPPOA_LLC:
		/* make sure llc header is present and remove */
		if (skb->len < sizeof(llc_ppp) ||
		    memcmp(skb->data, llc_ppp, sizeof(llc_ppp)))
			goto error;
		skb_pull(skb, sizeof(llc_ppp));
		break;

	case FBXATM_EPPPOA_AUTODETECT:
		/* look for lcp, with an llc header or not */
		if (skb->len >= sizeof(llc_ppp_lcp) &&
		    !memcmp(skb->data, llc_ppp_lcp, sizeof(llc_ppp_lcp))) {
			priv->cur_encap = FBXATM_EPPPOA_LLC;
			skb_pull(skb, sizeof(llc_ppp));
			break;
		}

		if (skb->len >= sizeof(lcp) &&
		    !memcmp(skb->data, lcp, sizeof (lcp))) {
			priv->cur_encap = FBXATM_EPPPOA_VCMUX;
			break;
		}

		/* no match */
		goto error;
	}

	ppp_input(&priv->chan, skb);
	return;

error:
	dev_kfree_skb(skb);
	ppp_input_error(&priv->chan, 0);
}

/*
 * fbxatm stack tx done callback, called from softirq
 */
static void vcc_tx_done_callback(void *data)
{
	struct fbxatm_pppoa_vcc *priv;
	priv = (struct fbxatm_pppoa_vcc *)data;
	ppp_output_wakeup(&priv->chan);
}

/*
 * vcc user ops, callback from fbxatm stack
 */
static const struct fbxatm_vcc_uops fbxatm_pppoa_vcc_uops = {
	.rx_pkt		= vcc_rx_callback,
	.tx_done	= vcc_tx_done_callback,
};

/*
 * ppp xmit callback
 */
static int ppp_xmit(struct ppp_channel *chan, struct sk_buff *skb)
{
	struct fbxatm_pppoa_vcc *priv;
	struct sk_buff *to_send_skb, *nskb;
	int ret;

	priv = (struct fbxatm_pppoa_vcc *)chan->private;

	/* MAYBE FIXME: handle protocol compression ? */

	to_send_skb = skb;
	nskb = NULL;

	/* send using vcmux encap if not yet known */
	switch (priv->cur_encap) {
	case FBXATM_EPPPOA_AUTODETECT:
	case FBXATM_EPPPOA_VCMUX:
		break;

	case FBXATM_EPPPOA_LLC:
	{
		unsigned int headroom;

		headroom = skb_headroom(skb);

		if (headroom < sizeof(llc_ppp)) {
			headroom += sizeof(llc_ppp);
			nskb = skb_realloc_headroom(skb, headroom);
			if (!nskb) {
				dev_kfree_skb(skb);
				return 1;
			}
			to_send_skb = nskb;
		}

		skb_push(to_send_skb, sizeof(llc_ppp));
		memcpy(to_send_skb->data, llc_ppp, sizeof(llc_ppp));
		break;
	}
	}

	ret = fbxatm_send(priv->vcc, to_send_skb);
	if (ret) {
		/* packet was not sent, queue is full, free any newly
		 * created skb */
		if (nskb)
			dev_kfree_skb(nskb);
		else {
			/* restore original skb if we altered it */
			if (priv->cur_encap == FBXATM_EPPPOA_LLC)
				skb_pull(skb, sizeof(llc_ppp));
		}

		/* suspend ppp output, will be woken up by
		 * ppp_output_wakeup, we're called under ppp lock so
		 * we can't race with tx done */
		return 0;
	}

	/* packet was sent, if we sent a copy free the original */
	if (nskb)
		dev_kfree_skb(skb);

	if (fbxatm_vcc_queue_full(priv->vcc))
		ppp_output_stop(chan);

	return 1;
}

static int ppp_ioctl(struct ppp_channel *chan, unsigned int cmd,
		     unsigned long arg)
{
	struct fbxatm_pppoa_vcc *priv;
	int ret;

	priv = (struct fbxatm_pppoa_vcc *)chan->private;

	switch (cmd) {
	case PPPIOCGFLAGS:
		ret = put_user(priv->flags, (int __user *)arg) ? -EFAULT : 0;
		break;
	case PPPIOCSFLAGS:
		ret = get_user(priv->flags, (int __user *) arg) ? -EFAULT : 0;
		break;
	default:
		ret = -ENOTTY;
		break;
	}
	return ret;
}

static struct ppp_channel_ops fbxatm_pppoa_ppp_ops = {
	.start_xmit = ppp_xmit,
	.ioctl = ppp_ioctl,
};

/*
 * find pppoa vcc from id
 */
static struct fbxatm_pppoa_vcc *
__find_pppoa_vcc(const struct fbxatm_vcc_id *id)
{
	struct fbxatm_pppoa_vcc *priv;
	int found;

	/* find it */
	found = 0;
	list_for_each_entry(priv, &fbxatm_pppoa_vcc_list, next) {
		if (priv->vcc->adev->ifindex != id->dev_idx ||
		    priv->vcc->vpi != id->vpi ||
		    priv->vcc->vci != id->vci)
			continue;

		found = 1;
		break;
	}

	if (found)
		return priv;
	return NULL;
}

/*
 * find pppoa vcc from socket
 */
static struct fbxatm_pppoa_vcc *
__find_pppoa_vcc_from_socket(const struct socket *sock)
{
	struct fbxatm_pppoa_vcc *priv;
	int found;

	/* find it */
	found = 0;
	list_for_each_entry(priv, &fbxatm_pppoa_vcc_list, next) {
		if (priv->sock != sock)
			continue;

		found = 1;
		break;
	}

	if (found)
		return priv;
	return NULL;
}

/*
 * bind to given vcc
 */
static int __bind_pppoa_vcc(const struct fbxatm_pppoa_vcc_params *params,
			    struct socket *sock)
{
	struct fbxatm_pppoa_vcc *priv;
	int ret;

	/* sanity check */
	switch (params->encap) {
	case FBXATM_EPPPOA_AUTODETECT:
	case FBXATM_EPPPOA_VCMUX:
	case FBXATM_EPPPOA_LLC:
		break;
	default:
		return -EINVAL;
	}

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;
	memcpy(&priv->params, params, sizeof (*params));
	priv->cur_encap = params->encap;

	/* bind to vcc */
	priv->vcc = fbxatm_bind_to_vcc(&params->id, FBXATM_VCC_USER_PPPOA);
	if (IS_ERR(priv->vcc)) {
		ret = PTR_ERR(priv->vcc);
		goto fail;
	}

	fbxatm_set_uops(priv->vcc, &fbxatm_pppoa_vcc_uops, priv);
	priv->chan.private = priv;
	priv->chan.ops = &fbxatm_pppoa_ppp_ops;
	priv->chan.mtu = priv->vcc->qos.max_sdu - PPP_HDRLEN;
	priv->chan.hdrlen = 0;
	priv->sock = sock;

	if (priv->cur_encap != FBXATM_EPPPOA_VCMUX) {
		/* assume worst case if vcmux is not forced */
		priv->chan.mtu -= sizeof(llc_ppp);
		priv->chan.hdrlen += sizeof(llc_ppp);
	}

	priv->chan.mtu -= priv->vcc->adev->tx_headroom;
	priv->chan.hdrlen += priv->vcc->adev->tx_headroom;

	ret = ppp_register_channel(&priv->chan);
	if (ret)
		goto fail_unbind;
	list_add_tail(&priv->next, &fbxatm_pppoa_vcc_list);
	return 0;

fail_unbind:
	fbxatm_unbind_vcc(priv->vcc);

fail:
	kfree(priv);
	return ret;
}

/*
 * bind to given vcc
 */
static int bind_pppoa_vcc(const struct fbxatm_pppoa_vcc_params *params,
			  struct socket *sock)
{
	int ret;

	mutex_lock(&fbxatm_pppoa_mutex);
	ret = __bind_pppoa_vcc(params, sock);
	mutex_unlock(&fbxatm_pppoa_mutex);
	return ret;
}

/*
 * unbind from given vcc
 */
static void __unbind_pppoa_vcc(struct fbxatm_pppoa_vcc *priv)
{
	ppp_unregister_channel(&priv->chan);
	fbxatm_unbind_vcc(priv->vcc);
	list_del(&priv->next);
	kfree(priv);
}

/*
 * unbind from given vcc
 */
static int unbind_pppoa_vcc(const struct fbxatm_pppoa_vcc_params *params)
{
	struct fbxatm_pppoa_vcc *priv;
	int ret;

	ret = 0;
	mutex_lock(&fbxatm_pppoa_mutex);
	priv = __find_pppoa_vcc(&params->id);
	if (!priv)
		ret = -ENOENT;
	else
		__unbind_pppoa_vcc(priv);
	mutex_unlock(&fbxatm_pppoa_mutex);
	return ret;
}

/*
 * pppoa related ioctl handler
 */
static int fbxatm_pppoa_ioctl(struct socket *sock,
			      unsigned int cmd, void __user *useraddr)
{
	int ret;

	ret = 0;

	switch (cmd) {
	case FBXATM_PPPOA_IOCADD:
	case FBXATM_PPPOA_IOCDEL:
	{
		struct fbxatm_pppoa_vcc_params params;

		if (copy_from_user(&params, useraddr, sizeof(params)))
			return -EFAULT;

		if (cmd == FBXATM_PPPOA_IOCADD)
			ret = bind_pppoa_vcc(&params, sock);
		else
			ret = unbind_pppoa_vcc(&params);
		break;
	}

	case FBXATM_PPPOA_IOCGET:
	{
		struct fbxatm_pppoa_vcc_params params;
		struct fbxatm_pppoa_vcc *priv;

		if (copy_from_user(&params, useraddr, sizeof(params)))
			return -EFAULT;

		mutex_lock(&fbxatm_pppoa_mutex);
		priv = __find_pppoa_vcc(&params.id);
		if (!priv)
			ret = -ENOENT;
		else
			memcpy(&params, &priv->params, sizeof (params));
		mutex_unlock(&fbxatm_pppoa_mutex);

		if (ret)
			return ret;

		if (copy_to_user(useraddr, &params, sizeof(params)))
			return -EFAULT;
		break;
	}

	case PPPIOCGCHAN:
	case PPPIOCGUNIT:
	{
		struct fbxatm_pppoa_vcc *priv;
		int value;

		value = 0;

		mutex_lock(&fbxatm_pppoa_mutex);
		priv = __find_pppoa_vcc_from_socket(sock);
		if (!priv)
			ret = -ENOENT;
		else {
			if (cmd == PPPIOCGCHAN)
				value = ppp_channel_index(&priv->chan);
			else
				value = ppp_unit_number(&priv->chan);
		}
		mutex_unlock(&fbxatm_pppoa_mutex);

		if (ret)
			return ret;

		if (copy_to_user(useraddr, &value, sizeof(value)))
			ret = -EFAULT;
		break;
	}

	default:
		return -ENOIOCTLCMD;
	}

	return ret;
}

/*
 * pppoa related release handler
 */
static void fbxatm_pppoa_release(struct socket *sock)
{
	struct fbxatm_pppoa_vcc *priv;

	mutex_lock(&fbxatm_pppoa_mutex);
	priv = __find_pppoa_vcc_from_socket(sock);
	if (priv)
		__unbind_pppoa_vcc(priv);
	mutex_unlock(&fbxatm_pppoa_mutex);
}

static struct fbxatm_ioctl fbxatm_pppoa_ioctl_ops = {
	.handler	= fbxatm_pppoa_ioctl,
	.release	= fbxatm_pppoa_release,
	.owner		= THIS_MODULE,
};

int __init fbxatm_pppoa_init(void)
{
	fbxatm_register_ioctl(&fbxatm_pppoa_ioctl_ops);
	return 0;
}

void fbxatm_pppoa_exit(void)
{
	fbxatm_unregister_ioctl(&fbxatm_pppoa_ioctl_ops);
}
