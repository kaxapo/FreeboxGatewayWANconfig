#ifndef LINUX_FBXATM_DEV_H_
#define LINUX_FBXATM_DEV_H_

#include <linux/types.h>
#include <linux/list.h>
#include <linux/err.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <linux/skbuff.h>
#include <linux/mutex.h>
#include <linux/fbxatm.h>
#include <linux/device.h>
#include <asm/atomic.h>
#include <linux/if_vlan.h>
#include <linux/fbxatm_remote.h>

/*
 * atm cell helper
 */
#define ATM_CELL_HDR_SIZE	5

#define ATM_GET_GFC(h)		(((h)[0] & 0xf0) >> 4)
#define ATM_SET_GFC(h,v)	do {					\
					(h)[0] &= ~0xf0;		\
					(h)[0] |= (v) << 4;		\
				} while (0)

#define ATM_GET_VPI(h)		((((h)[0] & 0x0f) << 4) |		\
				 (((h)[1] & 0xf0) >> 4))
#define ATM_SET_VPI(h,v)	do {					\
					(h)[0] &= ~0xf;			\
					(h)[1] &= ~0xf0;		\
					(h)[0] |= (v) >> 4;		\
					(h)[1] |= ((v) & 0xf) << 4;	\
				} while (0)

#define ATM_GET_VCI(h)		((((h)[1] & 0x0f) << 12) |		\
				 ((h)[2] << 4) |			\
				 ((((h)[3] & 0xf0) >> 4)))
#define ATM_SET_VCI(h,v)	do {					\
					(h)[1] &= ~0xf;			\
					(h)[3] &= ~0xf0;		\
					(h)[1] |= (v) >> 12;		\
					(h)[2] = ((v) & 0xff0) >> 4;	\
					(h)[3] |= ((v) & 0xf) << 4;	\
				} while (0)


#define ATM_GET_PT(h)		(((h)[3] & 0x0e) >> 1)
#define ATM_SET_PT(h,v)		do {					\
					(h)[3] &= ~0xe;			\
					(h)[3] |= (v) << 1;		\
				} while (0)

#define ATM_GET_CLP(h)		(((h)[3] & 0x01))
#define ATM_SET_CLP(h,v)	do {					\
					(h)[3] &= ~1;			\
					(h)[3] |= (v);			\
				} while (0)

#define ATM_GET_HEC(h)		((h)[4])
#define ATM_SET_HEC(h,v)	do {					\
					(h)[4] = (v);			\
				} while (0)


/*
 * OAM definition
 */
#define OAM_VCI_SEG_F4			3
#define OAM_VCI_END2END_F4		4

#define OAM_PTI_SEG_F5			0x4
#define OAM_PTI_END2END_F5		0x5

#define OAM_TYPE_SHIFT			4
#define OAM_TYPE_MASK			(0xf << OAM_TYPE_SHIFT)
#define OAM_TYPE_FAULT_MANAGEMENT	0x1
#define OAM_TYPE_PERF_MANAGEMENT	0x2
#define OAM_TYPE_ACTIVATION		0x8

#define FUNC_TYPE_SHIFT			0
#define FUNC_TYPE_MASK			(0xf << FUNC_TYPE_SHIFT)
#define FUNC_TYPE_AIS			0x0
#define FUNC_TYPE_FERF			0x1
#define FUNC_TYPE_CONT_CHECK		0x4
#define FUNC_TYPE_OAM_LOOPBACK		0x8

struct fbxatm_oam_cell_payload {
	u8			cell_hdr[5];
	u8			cell_type;
	u8			loopback_indication;
	u8			correlation_tag[4];
	u8			loopback_id[16];
	u8			source_id[16];
	u8			reserved[8];
	u8			crc10[2];
};

struct fbxatm_oam_cell {
	struct fbxatm_oam_cell_payload	payload;
	struct list_head		next;
};

struct fbxatm_oam_ping {
	struct fbxatm_oam_ping_req	req;
	u32				correlation_id;
	int				replied;
	wait_queue_head_t		wq;
	struct list_head		next;
};

/*
 * vcc/device stats
 */
struct fbxatm_vcc_stats {
	unsigned long			rx_bytes;
	unsigned long			tx_bytes;
	unsigned long			rx_aal5;
	unsigned long			tx_aal5;
};

struct fbxatm_dev_stats {
	unsigned long			rx_bytes;
	unsigned long			tx_bytes;
	unsigned long			rx_aal5;
	unsigned long			tx_aal5;
	unsigned long			rx_f4_oam;
	unsigned long			tx_f4_oam;
	unsigned long			rx_f5_oam;
	unsigned long			tx_f5_oam;
	unsigned long			rx_bad_oam;
	unsigned long			rx_bad_llid_oam;
	unsigned long			rx_other_oam;
	unsigned long			rx_dropped;
	unsigned long			tx_drop_nolink;
};

/*
 * vcc user ops
 */
struct fbxatm_vcc_uops {
	void	(*link_change)(void *cb_data, int link,
			       unsigned int rx_cell_rate,
			       unsigned int tx_cell_rate);
	void	(*rx_pkt)(struct sk_buff *skb, void *cb_data);
	void	(*tx_done)(void *cb_data);
};

/*
 * vcc status flags
 */
enum {
	FBXATM_VCC_F_FULL		= (1 << 0),

	FBXATM_VCC_F_LINK_UP		= (1 << 1),
};


/*
 * vcc definition
 */
struct fbxatm_dev;

struct fbxatm_vcc {
	unsigned int			vpi;
	unsigned int			vci;

	struct fbxatm_vcc_qos		qos;

	struct fbxatm_vcc_stats		stats;

	enum fbxatm_vcc_user		user;
	void				*user_priv;

	struct fbxatm_dev		*adev;
	void				*dev_priv;

	spinlock_t			user_ops_lock;
	const struct fbxatm_vcc_uops	*user_ops;
	void				*user_cb_data;

	unsigned int			to_drop_pkt;

	spinlock_t			tx_lock;
	unsigned long			vcc_flags;

	struct list_head		next;
};

/*
 * fbxatm device operation
 */
struct fbxatm_dev_ops {
	int (*open)(struct fbxatm_vcc *vcc);

	void (*close)(struct fbxatm_vcc *vcc);

	int (*ioctl)(struct fbxatm_dev *adev,
		     unsigned int cmd, void __user *arg);

	int (*send)(struct fbxatm_vcc *vcc, struct sk_buff *skb);

	int (*send_oam)(struct fbxatm_dev *adev,
			struct fbxatm_oam_cell *cell);

	int (*init_procfs)(struct fbxatm_dev *adev);
	void (*release_procfs)(struct fbxatm_dev *adev);

	struct module			*owner;
};

/*
 * device flags
 */
enum {
	FBXATM_DEV_F_LINK_UP		= (1 << 0),
};

/*
 * fbxatm device definition
 */
struct fbxatm_dev {
	int				ifindex;
	unsigned long			dev_flags;

	unsigned int			max_vcc;
	unsigned int			vci_mask;
	unsigned int			vpi_mask;
	unsigned int			max_priority;
	unsigned int			max_rx_priority;
	unsigned int			tx_headroom;

	char				*name;

	/* unit: b/s */
	unsigned int			link_rate_ds;
	unsigned int			link_rate_us;

	unsigned int			link_cell_rate_ds;
	unsigned int			link_cell_rate_us;

	const struct fbxatm_dev_ops	*ops;

	spinlock_t			stats_lock;
	struct fbxatm_dev_stats		stats;

	struct list_head		vcc_list;

	struct device			dev;

	spinlock_t			oam_lock;
	struct list_head		rx_oam_cells;
	unsigned int			rx_oam_cells_count;
	struct work_struct		oam_work;

	struct list_head		oam_pending_ping;
	u32				oam_correlation_id;

	struct proc_dir_entry		*dev_proc_entry;
	void				*priv;
	struct list_head		next;
};

/*
 * API for device drivers
 */
struct fbxatm_dev *fbxatm_alloc_device(int sizeof_priv);

int fbxatm_register_device(struct fbxatm_dev *adev,
			   const char *base_name,
			   const struct fbxatm_dev_ops *ops);

void fbxatm_free_device(struct fbxatm_dev *adev);

void fbxatm_dev_set_link_up(struct fbxatm_dev *adev);

void fbxatm_dev_set_link_down(struct fbxatm_dev *adev);

int fbxatm_unregister_device(struct fbxatm_dev *adev);

void fbxatm_netifrx_oam(struct fbxatm_dev *adev,
			struct fbxatm_oam_cell *cell);


static inline int fbxatm_vcc_link_is_up(struct fbxatm_vcc *vcc)
{
	return test_bit(FBXATM_VCC_F_LINK_UP, &vcc->vcc_flags);
}

#define	FBXATMDEV_ALIGN		4

static inline void *fbxatm_dev_priv(struct fbxatm_dev *adev)
{
	return (u8 *)adev + ((sizeof(struct fbxatm_dev)
			      + (FBXATMDEV_ALIGN - 1))
			     & ~(FBXATMDEV_ALIGN - 1));
}

/*
 * API for FBXATM stack user
 */
struct fbxatm_ioctl {
	int (*handler)(struct socket *sock,
		       unsigned int cmd, void __user *useraddr);

	void (*release)(struct socket *sock);

	struct module		*owner;
	struct list_head	next;
};

void fbxatm_set_uops(struct fbxatm_vcc *vcc,
		     const struct fbxatm_vcc_uops *user_ops,
		     void *user_cb_data);

struct fbxatm_vcc *
fbxatm_bind_to_vcc(const struct fbxatm_vcc_id *id,
		   enum fbxatm_vcc_user user);

void fbxatm_unbind_vcc(struct fbxatm_vcc *vcc);


static inline int fbxatm_vcc_queue_full(struct fbxatm_vcc *vcc)
{
	return test_bit(FBXATM_VCC_F_FULL, &vcc->vcc_flags);
}

#ifdef CONFIG_FBXATM_STACK
/*
 * stack user callback to send data on given vcc
 */
static inline int fbxatm_send(struct fbxatm_vcc *vcc, struct sk_buff *skb)
{
	int ret;
	unsigned int len;

	len = skb->len;

	spin_lock_bh(&vcc->tx_lock);
	if (!test_bit(FBXATM_VCC_F_LINK_UP, &vcc->vcc_flags)) {
		spin_unlock_bh(&vcc->tx_lock);
		dev_kfree_skb(skb);
		spin_lock(&vcc->adev->stats_lock);
		vcc->adev->stats.tx_drop_nolink++;
		spin_unlock(&vcc->adev->stats_lock);
		return 0;
	}

	ret = vcc->adev->ops->send(vcc, skb);
	if (!ret) {
		vcc->stats.tx_bytes += len;
		vcc->stats.tx_aal5++;
	}
	spin_unlock_bh(&vcc->tx_lock);

	if (!ret) {
		spin_lock_bh(&vcc->adev->stats_lock);
		vcc->adev->stats.tx_bytes += len;
		vcc->adev->stats.tx_aal5++;
		spin_unlock_bh(&vcc->adev->stats_lock);
	}
	return ret;
}

/*
 * device callback when packet comes in
 */
static inline void fbxatm_netifrx(struct fbxatm_vcc *vcc, struct sk_buff *skb)
{
	unsigned int len;

	len = skb->len;

	spin_lock_bh(&vcc->user_ops_lock);
	if (!vcc->user_ops) {
		spin_unlock_bh(&vcc->user_ops_lock);
		dev_kfree_skb(skb);
		return;
	}

	if (vcc->to_drop_pkt) {
		vcc->to_drop_pkt--;
		spin_unlock_bh(&vcc->user_ops_lock);
		dev_kfree_skb(skb);
		return;
	}

	vcc->stats.rx_bytes += len;
	vcc->stats.rx_aal5++;

	vcc->user_ops->rx_pkt(skb, vcc->user_cb_data);
	spin_unlock_bh(&vcc->user_ops_lock);

	spin_lock_bh(&vcc->adev->stats_lock);
	vcc->adev->stats.rx_bytes += len;
	vcc->adev->stats.rx_aal5++;
	spin_unlock_bh(&vcc->adev->stats_lock);
}

/*
 * device callback when tx is done on vcc
 */
static inline void fbxatm_tx_done(struct fbxatm_vcc *vcc)
{
	spin_lock_bh(&vcc->user_ops_lock);
	if (vcc->user_ops)
		vcc->user_ops->tx_done(vcc->user_cb_data);
	spin_unlock_bh(&vcc->user_ops_lock);
}
#else
int fbxatm_send(struct fbxatm_vcc *vcc, struct sk_buff *skb);
void fbxatm_netifrx(struct fbxatm_vcc *vcc, struct sk_buff *skb);
void fbxatm_tx_done(struct fbxatm_vcc *vcc);
#endif

static inline unsigned int fbxatm_rx_reserve(void)
{
#ifdef CONFIG_FBXATM_STACK
	/* normal stack, no headroom needed */
	return 0;
#else
	/* remote stub, we need to send rx skb to another location,
	 * adding the fbxatm_remote header, an ethernet header (with
	 * possible vlan) */
	return ALIGN(sizeof (struct fbxatm_remote_hdr) + VLAN_ETH_HLEN, 4);
#endif
}

void fbxatm_register_ioctl(struct fbxatm_ioctl *ioctl);

void fbxatm_unregister_ioctl(struct fbxatm_ioctl *ioctl);

#endif /* !LINUX_FBXATM_DEV_H_ */
