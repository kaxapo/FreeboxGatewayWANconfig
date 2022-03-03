#ifndef FBXATM_REMOTE_DRIVER_H_
#define FBXATM_REMOTE_DRIVER_H_

#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/fbxatm.h>
#include <linux/fbxatm_dev.h>
#include <linux/fbxatm_remote.h>

enum remote_state {
	RSTATE_S_WAIT_NETDEV = 0,
	RSTATE_S_WAIT_REMOTE,
	RSTATE_S_ACTIVE,
	RSTATE_S_DEAD,
};

struct driver_remote;

struct driver_remote_vcc {

	struct fbxatm_vcc		*vcc;
	struct driver_remote		*priv;

	unsigned int			remote_id;

	int				tx_pending;
	int				tx_got_qempty;

	/* output */
	struct fbxatm_remote_sock	*vcc_send_sock;

	/* input */
	struct fbxatm_remote_sock	*vcc_rx_sock;
	struct fbxatm_remote_sock	*vcc_qempty_sock;

	struct list_head		next;
};

struct driver_remote {
	struct fbxatm_dev		*fbxatm_dev;
	int				fbxatm_dev_registered;

	struct list_head		pvcc_list;

	spinlock_t			tx_lock;
	struct mutex			mutex;

	struct fbxatm_remote_ctx	*remote_ctx;
	struct net_device		*netdev;

	enum remote_state		state;
	struct delayed_work		fsm_work;
	int				want_die;

	/* output */
	struct fbxatm_remote_sock	*dev_connect_sock;
	struct sk_buff_head		connect_acks;

	struct fbxatm_remote_sock	*keepalive_sock;

	/* input */
	struct fbxatm_remote_sock	*dev_link_sock;
	struct sk_buff_head		dev_link_reqs;

	struct fbxatm_remote_sock	*dev_rx_oam_sock;
	struct sk_buff_head		dev_oam_reqs;

	/* used to wait for send_oam & vcc_action */
	struct fbxatm_remote_sock	*vcc_action_sock;
	struct fbxatm_remote_sock	*dev_send_oam_sock;
	wait_queue_head_t		wq;
	int				wq_res;
	struct sk_buff_head		wq_acks;

	struct fbxatm_remote_pdata	*pd;
	struct list_head		next;
};

#endif /* ! FBXATM_REMOTE_DRIVER_H_ */
