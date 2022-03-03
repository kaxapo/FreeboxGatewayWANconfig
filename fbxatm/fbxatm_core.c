#include <linux/init.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/fbxatm.h>
#include <linux/fbxatm_dev.h>
#include <linux/module.h>
#include <net/sock.h>
#include "fbxatm_priv.h"

static DEFINE_MUTEX(ioctl_mutex);
static LIST_HEAD(ioctl_list);

void fbxatm_register_ioctl(struct fbxatm_ioctl *ioctl)
{
	mutex_lock(&ioctl_mutex);
	list_add_tail(&ioctl->next, &ioctl_list);
	mutex_unlock(&ioctl_mutex);
}

void fbxatm_unregister_ioctl(struct fbxatm_ioctl *ioctl)
{
	mutex_lock(&ioctl_mutex);
	list_del(&ioctl->next);
	mutex_unlock(&ioctl_mutex);
}

static int fbxatm_sock_ioctl(struct socket *sock, unsigned int cmd,
			     unsigned long arg)
{
	struct fbxatm_ioctl *ioctl;
	void __user *useraddr;
	int ret;

	/* sanity check */
	useraddr = (void __user *)arg;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	ret = -ENOIOCTLCMD;
	mutex_lock(&ioctl_mutex);

	list_for_each_entry(ioctl, &ioctl_list, next) {
		if (!ioctl->handler)
			continue;

		if (!try_module_get(ioctl->owner))
			continue;

		ret = ioctl->handler(sock, cmd, useraddr);
		module_put(ioctl->owner);
		if (ret != -ENOIOCTLCMD)
			break;
	}
	mutex_unlock(&ioctl_mutex);

	return ret;
}

static int fbxatm_sock_release(struct socket *sock)
{
	struct fbxatm_ioctl *ioctl;
	struct sock *sk = sock->sk;

	mutex_lock(&ioctl_mutex);

	list_for_each_entry(ioctl, &ioctl_list, next) {
		if (!ioctl->release)
			continue;

		if (!try_module_get(ioctl->owner))
			continue;

		ioctl->release(sock);
		module_put(ioctl->owner);
	}
	mutex_unlock(&ioctl_mutex);

	if (sk)
		sock_put(sk);

	return 0;
}

static const struct proto_ops fbxatm_proto_ops = {
	.family		= PF_FBXATM,

	.release =	fbxatm_sock_release,
	.ioctl =	fbxatm_sock_ioctl,

	.bind =		sock_no_bind,
	.connect =	sock_no_connect,
	.socketpair =	sock_no_socketpair,
	.accept =	sock_no_accept,
	.getname =	sock_no_getname,
	.poll =		sock_no_poll,
	.listen =	sock_no_listen,
	.shutdown =	sock_no_shutdown,
	.setsockopt =	sock_no_setsockopt,
	.getsockopt =	sock_no_getsockopt,
	.sendmsg =	sock_no_sendmsg,
	.recvmsg =	sock_no_recvmsg,
	.mmap =		sock_no_mmap,
	.sendpage =	sock_no_sendpage,
	.owner		= THIS_MODULE,
};

static struct proto fbxatm_proto = {
        .name           = "fbxatm",
        .owner          =  THIS_MODULE,
        .obj_size       = sizeof (struct sock),
};

static int fbxatm_sock_create(struct net *net, struct socket *sock,
			      int protocol, int kern)
{
	struct sock *sk;

        sk = sk_alloc(net, PF_FBXATM, GFP_KERNEL, &fbxatm_proto, kern);
	if (!sk)
		return -ENOMEM;

        sock_init_data(sock, sk);
        sock->state = SS_UNCONNECTED;
        sock->ops = &fbxatm_proto_ops;
	return 0;
}

static struct net_proto_family fbxatm_family_ops = {
	.family = PF_FBXATM,
	.create = fbxatm_sock_create,
	.owner = THIS_MODULE,
};


static int __init fbxatm_init(void)
{
	int ret;

	printk(KERN_INFO "Freebox ATM stack\n");
	ret = fbxatm_sysfs_init();
	if (ret)
		return ret;

	ret = fbxatm_procfs_init();
	if (ret)
		goto fail_sysfs;

	ret = fbxatm_vcc_init();
	if (ret)
		goto fail_procfs;

	ret = fbxatm_2684_init();
	if (ret)
		goto fail_vcc;

	ret = fbxatm_pppoa_init();
	if (ret)
		goto fail_2684;

	ret = proto_register(&fbxatm_proto, 0);
	if (ret)
		goto fail_pppoa;

	ret = sock_register(&fbxatm_family_ops);
	if (ret)
		goto fail_proto;

	return 0;

fail_proto:
	proto_unregister(&fbxatm_proto);

fail_pppoa:
	fbxatm_pppoa_exit();

fail_2684:
	fbxatm_2684_exit();

fail_vcc:
	fbxatm_vcc_exit();

fail_procfs:
	fbxatm_procfs_exit();

fail_sysfs:
	fbxatm_sysfs_exit();
	printk(KERN_ERR "failed to initialize Freebox ATM stack\n");
	return ret;
}

static void __exit fbxatm_exit(void)
{
	sock_unregister(PF_FBXATM);
	proto_unregister(&fbxatm_proto);
	fbxatm_pppoa_exit();
	fbxatm_2684_exit();
	fbxatm_vcc_exit();
	fbxatm_procfs_exit();
	fbxatm_sysfs_exit();
}

subsys_initcall(fbxatm_init);
module_exit(fbxatm_exit);

MODULE_LICENSE("GPL");
MODULE_ALIAS_NETPROTO(PF_FBXATM);
