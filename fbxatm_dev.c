#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/bitops.h>
#include <linux/fbxatm_dev.h>
#include "fbxatm_priv.h"

/*
 * list of registered device & lock
 */
LIST_HEAD(fbxatm_dev_list);

/*
 * big "rtnl" lock
 */
DEFINE_MUTEX(fbxatm_mutex);
static int fbxatm_ifindex = -1;

/*
 * find device by index
 */
static struct fbxatm_dev *__fbxatm_dev_get_by_index(int ifindex)
{
	struct fbxatm_dev *pdev;

	list_for_each_entry(pdev, &fbxatm_dev_list, next) {
		if (pdev->ifindex == ifindex)
			return pdev;
	}
	return NULL;
}

/*
 * find vcc by id
 */
static struct fbxatm_vcc *
__fbxatm_vcc_get_by_id(const struct fbxatm_vcc_id *id)
{
	struct fbxatm_dev *adev;
	struct fbxatm_vcc *vcc;
	int found;

	adev = __fbxatm_dev_get_by_index(id->dev_idx);
	if (!adev)
		return ERR_PTR(-ENODEV);

	found = 0;
	list_for_each_entry(vcc, &adev->vcc_list, next) {
		if (vcc->vpi != id->vpi || vcc->vci != id->vci)
			continue;
		found = 1;
		break;
	}

	if (found)
		return vcc;
	return ERR_PTR(-ENOENT);
}

/*
 * allocate device
 */
struct fbxatm_dev *fbxatm_alloc_device(int sizeof_priv)
{
	unsigned int size;

	size = sizeof(struct fbxatm_dev) + sizeof_priv + FBXATMDEV_ALIGN;
	return kzalloc(size, GFP_KERNEL);
}

EXPORT_SYMBOL(fbxatm_alloc_device);

/*
 * calculate crc10 of oam cell
 */
static void compute_oam_crc10(struct fbxatm_oam_cell_payload *cell)
{
	u8 *pdu;
	u16 crc;

	/* crc10 does not cover header */
	pdu = (u8 *)&cell->cell_type;
	memset(cell->crc10, 0, 2);

	crc = crc10(0, pdu, sizeof (*cell) - sizeof (cell->cell_hdr));
	cell->crc10[0] = crc >> 8;
	cell->crc10[1] = crc & 0xff;
}

/*
 * check crc10 of oam cell
 */
static int check_oam_crc10(struct fbxatm_oam_cell_payload *cell)
{
	u8 *pdu;
	u16 crc;

	pdu = (u8 *)&cell->cell_type;

	crc = (cell->crc10[0] << 8) | cell->crc10[1];
	memset(cell->crc10, 0, 2);

	if (crc != crc10(0, pdu, sizeof (*cell) - sizeof (cell->cell_hdr)))
		return 1;

	return 0;
}

/*
 * send an oam ping and wait for answer
 */
static int do_oam_ping(struct fbxatm_oam_ping *ping)
{
	struct fbxatm_dev *adev;
	struct fbxatm_oam_cell *oam_cell;
	struct fbxatm_oam_cell_payload *cell;
	u8 *hdr;
	int ret;

	switch (ping->req.type) {
	case FBXATM_OAM_PING_SEG_F4:
	case FBXATM_OAM_PING_E2E_F4:
		return -ENOTSUPP;
	case FBXATM_OAM_PING_SEG_F5:
	case FBXATM_OAM_PING_E2E_F5:
		break;
	default:
		return -EINVAL;
	}

	/* find device */
	mutex_lock(&fbxatm_mutex);
	adev = __fbxatm_dev_get_by_index(ping->req.id.dev_idx);
	if (!adev) {
		ret = -ENODEV;
		goto out_unlock;
	}

	if (!test_bit(FBXATM_DEV_F_LINK_UP, &adev->dev_flags)) {
		ret = -ENETDOWN;
		goto out_unlock;
	}

	/* if f5, vcc need to be opened */
	switch (ping->req.type) {
	case FBXATM_OAM_PING_SEG_F5:
	case FBXATM_OAM_PING_E2E_F5:
	{
		struct fbxatm_vcc *vcc;

		vcc = __fbxatm_vcc_get_by_id(&ping->req.id);
		if (IS_ERR(vcc)) {
			ret = -ENETDOWN;
			goto out_unlock;
		}
		break;
	}

	default:
		break;
	}

	ping->correlation_id = ++adev->oam_correlation_id;

	/* prepare atm oam cell and send it */
	oam_cell = kmalloc(sizeof (*oam_cell), GFP_KERNEL);
	if (!oam_cell) {
		ret = -ENOMEM;
		goto out_unlock;
	}
	cell = &oam_cell->payload;

	hdr = cell->cell_hdr;
	ATM_SET_GFC(hdr, 0);

	ATM_SET_VPI(hdr, ping->req.id.vpi);
	ATM_SET_VCI(hdr, ping->req.id.vci);
	if (ping->req.type == FBXATM_OAM_PING_E2E_F5)
		ATM_SET_PT(hdr, OAM_PTI_END2END_F5);
	else
		ATM_SET_PT(hdr, OAM_PTI_SEG_F5);
	ATM_SET_CLP(hdr, 0);
	ATM_SET_HEC(hdr, 0);

	cell->cell_type = (OAM_TYPE_FAULT_MANAGEMENT << OAM_TYPE_SHIFT) |
		(FUNC_TYPE_OAM_LOOPBACK << FUNC_TYPE_SHIFT);
	cell->loopback_indication = 1;

	memcpy(cell->correlation_tag, &ping->correlation_id,
	       sizeof (cell->correlation_tag));
	memcpy(cell->loopback_id, ping->req.llid, sizeof (ping->req.llid));
	memset(cell->source_id, 0x6a, sizeof (cell->source_id));
	memset(cell->reserved, 0x6a, sizeof (cell->reserved));

	compute_oam_crc10(cell);

	ret = adev->ops->send_oam(adev, oam_cell);
	if (ret)
		goto out_unlock;

	/* wait for an answer */
	list_add(&ping->next, &adev->oam_pending_ping);
	ping->replied = 0;
	init_waitqueue_head(&ping->wq);
	mutex_unlock(&fbxatm_mutex);

	ret = wait_event_interruptible_timeout(ping->wq, ping->replied,
					       HZ * 5);
	list_del(&ping->next);

	if (ret == -ERESTARTSYS)
		return ret;

	if (ping->replied < 0) {
		/* ping failed */
		return ping->replied;
	}

	if (!ping->replied) {
		/* timeout */
		return -ETIME;
	}

	return 0;


out_unlock:
	mutex_unlock(&fbxatm_mutex);
	return ret;
}

/*
 * special llid values
 */
static const u8 llid_all1[16] = { 0xff, 0xff, 0xff, 0xff,
				  0xff, 0xff, 0xff, 0xff,
				  0xff, 0xff, 0xff, 0xff,
				  0xff, 0xff, 0xff, 0xff };

static const u8 llid_all0[16] = { 0 };

/*
 * handle incoming oam cell
 */
static void handle_oam_cell(struct fbxatm_dev *adev,
			    struct fbxatm_oam_cell *oam_cell)
{
	struct fbxatm_oam_cell_payload *cell;
	u16 vci;
	u8 *hdr, pt, oam, func;

	/* check CRC10 */
	cell = &oam_cell->payload;
	if (check_oam_crc10(cell)) {
		adev->stats.rx_bad_oam++;
		goto out;
	}

	/* drop f4 cells */
	hdr = cell->cell_hdr;
	vci = ATM_GET_VCI(hdr);

	if (vci == OAM_VCI_SEG_F4 || vci == OAM_VCI_END2END_F4) {
		adev->stats.rx_f4_oam++;
		goto out;
	}

	/* keep f5 cells only */
	pt = ATM_GET_PT(hdr);
	if (pt != OAM_PTI_SEG_F5 && pt != OAM_PTI_END2END_F5) {
		adev->stats.rx_other_oam++;
		goto out;
	}

	adev->stats.rx_f5_oam++;

	/* keep oam loopback type only */
	oam = (cell->cell_type & OAM_TYPE_MASK) >> OAM_TYPE_SHIFT;
	func = (cell->cell_type & FUNC_TYPE_MASK) >> FUNC_TYPE_SHIFT;

	if (oam != OAM_TYPE_FAULT_MANAGEMENT ||
	    func != FUNC_TYPE_OAM_LOOPBACK) {
		adev->stats.rx_other_oam++;
		goto out;
	}

	if (cell->loopback_indication & 1) {
		int match, ret;

		/* request, check for llid match */
		match = 0;
		switch (pt) {
		case OAM_PTI_SEG_F5:
			/* 0x0 or 0xffffffff */
			if (!memcmp(cell->loopback_id, llid_all0,
				    sizeof (llid_all0)))
				match = 1;
			/* fallthrough */

		case OAM_PTI_END2END_F5:
			/* 0xffffffff only */
			if (!memcmp(cell->loopback_id, llid_all1,
				    sizeof (llid_all1)))
				match = 1;
			break;
		}

		if (!match) {
			adev->stats.rx_bad_llid_oam++;
			goto out;
		}

		/* ok, update llid and answer */
		cell->loopback_indication = 0;
		memcpy(cell->loopback_id, llid_all1, sizeof (llid_all1));
		compute_oam_crc10(cell);

		mutex_lock(&fbxatm_mutex);
		ret = adev->ops->send_oam(adev, oam_cell);
		mutex_unlock(&fbxatm_mutex);

		if (!ret) {
			/* send successful, don't free cell */
			return;
		}

	} else {
		struct fbxatm_oam_ping *ping;

		/* reply, find a matching sender */
		mutex_lock(&fbxatm_mutex);
		list_for_each_entry(ping, &adev->oam_pending_ping, next) {

			/* compare correlation id */
			if (memcmp(&ping->correlation_id,
				   cell->correlation_tag,
				   sizeof (cell->correlation_tag)))
				continue;

			/* compare ping type */
			switch (ping->req.type) {
			case FBXATM_OAM_PING_SEG_F5:
				if (pt != OAM_PTI_SEG_F5)
					continue;
				break;
			case FBXATM_OAM_PING_E2E_F5:
				if (pt != OAM_PTI_END2END_F5)
					continue;
				break;
			default:
				break;
			}

			/* seems we have a match */
			ping->replied = 1;
			wake_up(&ping->wq);
		}
		mutex_unlock(&fbxatm_mutex);
	}

out:
	kfree(oam_cell);
}

/*
 * oam rx processing workqueue
 */
static void fbxatm_oam_work(struct work_struct *work)
{
	struct fbxatm_dev *adev;
	struct fbxatm_oam_cell *cell;

	adev = container_of(work, struct fbxatm_dev, oam_work);

	do {
		cell = NULL;
		spin_lock_bh(&adev->oam_lock);
		if (!list_empty(&adev->rx_oam_cells)) {
			cell = list_first_entry(&adev->rx_oam_cells,
						struct fbxatm_oam_cell, next);
			list_del(&cell->next);
			adev->rx_oam_cells_count--;
		}
		spin_unlock_bh(&adev->oam_lock);

		if (cell)
			handle_oam_cell(adev, cell);

	} while (cell);
}

/*
 * register given device
 */
static int __fbxatm_register_device(struct fbxatm_dev *adev,
				    const char *base_name,
				    const struct fbxatm_dev_ops *ops)
{
	struct fbxatm_dev *pdev;
	int name_len, count, ret;
	long *inuse;

	adev->ops = ops;
	INIT_LIST_HEAD(&adev->vcc_list);
	INIT_LIST_HEAD(&adev->next);
	spin_lock_init(&adev->stats_lock);
	spin_lock_init(&adev->oam_lock);
	INIT_LIST_HEAD(&adev->rx_oam_cells);
	INIT_WORK(&adev->oam_work, fbxatm_oam_work);
	INIT_LIST_HEAD(&adev->oam_pending_ping);
	get_random_bytes(&adev->oam_correlation_id, 4);

	name_len = strlen(base_name);
	adev->name = kmalloc(name_len + 10, GFP_KERNEL);
	if (!adev->name) {
		ret = -ENOMEM;
		goto fail;
	}

	/* allocate ifindex */
	while (1) {
		if (++fbxatm_ifindex < 0)
			fbxatm_ifindex = 0;
		if (__fbxatm_dev_get_by_index(fbxatm_ifindex))
			continue;
		adev->ifindex = fbxatm_ifindex;
		break;
	}

	/* allocate device name */
	inuse = (long *)get_zeroed_page(GFP_ATOMIC);
	if (!inuse) {
		ret = -ENOMEM;
		goto fail;
	}

	list_for_each_entry(pdev, &fbxatm_dev_list, next) {
		unsigned long val;
		char *end;

		/* look for common prefix */
		if (strncmp(base_name, pdev->name, name_len))
			continue;

		/* make sure name is the same, not just a prefix */
		val = simple_strtoul(pdev->name + name_len, &end, 10);
		if (!*end)
			continue;

		set_bit(val, inuse);
	}

	count = find_first_zero_bit(inuse, PAGE_SIZE * 8);
	free_page((unsigned long)inuse);

	snprintf(adev->name, name_len + 10, "%s%d", base_name, count);
	list_add_tail(&adev->next, &fbxatm_dev_list);

	/* create procfs entries */
	ret = fbxatm_proc_dev_register(adev);
	if (ret)
		goto fail;

	/* call device procfs init if any */
	if (adev->ops->init_procfs) {
		ret = adev->ops->init_procfs(adev);
		if (ret)
			goto fail_procfs;
	}

	/* create sysfs entries */
	ret = fbxatm_register_dev_sysfs(adev);
	if (ret)
		goto fail_procfs;

	return 0;

fail_procfs:
	fbxatm_proc_dev_deregister(adev);

fail:
	list_del(&adev->next);
	kfree(adev->name);
	return ret;
}

/*
 * take lock and register device
 */
int fbxatm_register_device(struct fbxatm_dev *adev,
			   const char *base_name,
			   const struct fbxatm_dev_ops *ops)
{
	int ret;

	mutex_lock(&fbxatm_mutex);
	ret = __fbxatm_register_device(adev, base_name, ops);
	mutex_unlock(&fbxatm_mutex);
	return ret;
}

EXPORT_SYMBOL(fbxatm_register_device);

/*
 * change device "link" state
 */
static void fbxatm_dev_set_link(struct fbxatm_dev *adev, int link)
{
	struct fbxatm_vcc *vcc;

	/* prevent new vcc creation and oam ping */
	mutex_lock(&fbxatm_mutex);

	if (link) {
		memset(&adev->stats, 0, sizeof (adev->stats));
		list_for_each_entry(vcc, &adev->vcc_list, next)
			memset(&vcc->stats, 0, sizeof (vcc->stats));
		wmb();
		set_bit(FBXATM_DEV_F_LINK_UP, &adev->dev_flags);
		list_for_each_entry(vcc, &adev->vcc_list, next) {
			set_bit(FBXATM_VCC_F_LINK_UP, &vcc->vcc_flags);
			if (!vcc->user_ops || !vcc->user_ops->link_change)
				continue;
			vcc->user_ops->link_change(vcc->user_cb_data, 1,
						   adev->link_cell_rate_ds,
						   adev->link_cell_rate_us);
		}
	} else {
		/* prevent further oam cells input */
		spin_lock_bh(&adev->oam_lock);
		clear_bit(FBXATM_DEV_F_LINK_UP, &adev->dev_flags);
		spin_unlock_bh(&adev->oam_lock);

		/* flush rx oam work */
		cancel_work_sync(&adev->oam_work);

		/* now disable tx on all vcc */
		list_for_each_entry(vcc, &adev->vcc_list, next) {
			spin_lock_bh(&vcc->tx_lock);
			clear_bit(FBXATM_VCC_F_LINK_UP, &vcc->vcc_flags);
			spin_unlock_bh(&vcc->tx_lock);
			if (!vcc->user_ops || !vcc->user_ops->link_change)
				continue;
			vcc->user_ops->link_change(vcc->user_cb_data, 0, 0, 0);
		}
	}

	fbxatm_dev_change_sysfs(adev);
	mutex_unlock(&fbxatm_mutex);
}

/*
 * set device "link" to up, allowing vcc/device send ops to be called,
 * this function sleeps
 */
void fbxatm_dev_set_link_up(struct fbxatm_dev *adev)
{
	if (!test_bit(FBXATM_DEV_F_LINK_UP, &adev->dev_flags))
		printk(KERN_INFO "%s: link UP - "
		       "down: %u kbit/s - up: %u kbit/s\n", adev->name,
		       adev->link_rate_ds / 1000, adev->link_rate_us / 1000);
	return fbxatm_dev_set_link(adev, 1);
}

EXPORT_SYMBOL(fbxatm_dev_set_link_up);

/*
 * set device link to down, disallowing any vcc/device send ops to be
 * called, this function sleeps
 */
void fbxatm_dev_set_link_down(struct fbxatm_dev *adev)
{
	if (test_bit(FBXATM_DEV_F_LINK_UP, &adev->dev_flags))
		printk(KERN_INFO "%s: link DOWN\n", adev->name);
	return fbxatm_dev_set_link(adev, 0);
}

EXPORT_SYMBOL(fbxatm_dev_set_link_down);

/*
 * take lock and unregister device
 */
int fbxatm_unregister_device(struct fbxatm_dev *adev)
{
	int ret;

	ret = 0;
	mutex_lock(&fbxatm_mutex);

	if (!list_empty(&adev->vcc_list)) {
		ret = -EBUSY;
		goto out;
	}

	list_del(&adev->next);

	if (adev->ops->release_procfs)
		adev->ops->release_procfs(adev);
	fbxatm_proc_dev_deregister(adev);

	fbxatm_unregister_dev_sysfs(adev);
out:
	mutex_unlock(&fbxatm_mutex);
	return ret;
}

EXPORT_SYMBOL(fbxatm_unregister_device);

/*
 * actually free device memory
 */
void __fbxatm_free_device(struct fbxatm_dev *adev)
{
	kfree(adev->name);
	kfree(adev);
}

/*
 * free device memory
 */
void fbxatm_free_device(struct fbxatm_dev *adev)
{
	/* actual free is done in sysfs release */
//	class_device_put(&adev->class_dev);
}

EXPORT_SYMBOL(fbxatm_free_device);

/*
 * device callback when oam cell comes in
 */
void fbxatm_netifrx_oam(struct fbxatm_dev *adev, struct fbxatm_oam_cell *cell)
{
	spin_lock_bh(&adev->oam_lock);
	if (!test_bit(FBXATM_DEV_F_LINK_UP, &adev->dev_flags) ||
	    adev->rx_oam_cells_count > 8) {
		kfree(cell);
		spin_unlock_bh(&adev->oam_lock);
		return;
	}
	adev->rx_oam_cells_count++;
	list_add_tail(&cell->next, &adev->rx_oam_cells);
	spin_unlock_bh(&adev->oam_lock);
	schedule_work(&adev->oam_work);
}

EXPORT_SYMBOL(fbxatm_netifrx_oam);

/*
 * set user ops on vcc
 */
void fbxatm_set_uops(struct fbxatm_vcc *vcc,
		     const struct fbxatm_vcc_uops *user_ops,
		     void *user_cb_data)
{
	spin_lock_bh(&vcc->user_ops_lock);
	vcc->user_ops = user_ops;
	vcc->user_cb_data = user_cb_data;
	spin_unlock_bh(&vcc->user_ops_lock);
}

/*
 * bind to given vcc
 */
static struct fbxatm_vcc *
__fbxatm_bind_to_vcc(const struct fbxatm_vcc_id *id,
		     enum fbxatm_vcc_user user)
{
	struct fbxatm_vcc *vcc;

	vcc = __fbxatm_vcc_get_by_id(id);
	if (IS_ERR(vcc))
		return vcc;

	if (vcc->user != FBXATM_VCC_USER_NONE)
		return ERR_PTR(-EBUSY);

	vcc->user = user;
	return vcc;
}

/*
 * bind to given vcc
 */
struct fbxatm_vcc *
fbxatm_bind_to_vcc(const struct fbxatm_vcc_id *id,
		   enum fbxatm_vcc_user user)
{
	struct fbxatm_vcc *vcc;

	mutex_lock(&fbxatm_mutex);
	vcc = __fbxatm_bind_to_vcc(id, user);
	mutex_unlock(&fbxatm_mutex);
	return vcc;
}

/*
 * unbind from given vcc
 */
void fbxatm_unbind_vcc(struct fbxatm_vcc *vcc)
{
	spin_lock_bh(&vcc->user_ops_lock);
	vcc->user_ops = NULL;
	vcc->user_cb_data = NULL;
	vcc->user = FBXATM_VCC_USER_NONE;
	spin_unlock_bh(&vcc->user_ops_lock);
}

/*
 * open vcc on given device
 */
static int __fbxatm_dev_open_vcc(const struct fbxatm_vcc_id *id,
				 const struct fbxatm_vcc_qos *qos)
{
	struct fbxatm_vcc *vcc;
	struct fbxatm_dev *adev;
	int ret, count;

	/* check vpi/vci unicity  */
	vcc = __fbxatm_vcc_get_by_id(id);
	if (!IS_ERR(vcc))
		return -EBUSY;

	/* sanity check */
	switch (qos->traffic_class) {
	case FBXATM_VCC_TC_UBR_NO_PCR:
	case FBXATM_VCC_TC_UBR:
		break;
	default:
		return -EINVAL;
	}

	if (qos->max_sdu > 4096)
		return -EINVAL;

	if (!qos->max_buffered_pkt || qos->max_buffered_pkt > 128)
		return -EINVAL;

	adev = __fbxatm_dev_get_by_index(id->dev_idx);
	if (!adev)
		return -ENODEV;

	/* make sure device accept requested priorities */
	if (qos->priority > adev->max_priority)
		return -EINVAL;

	if (qos->rx_priority > adev->max_rx_priority)
		return -EINVAL;

	/* don't open more vcc than device can handle */
	count = 0;
	list_for_each_entry(vcc, &adev->vcc_list, next)
		count++;
	if (count + 1 > adev->max_vcc)
		return -ENOSPC;

	/* make sure vpi/vci is valid for this device */
	if ((~adev->vpi_mask & id->vpi) || (~adev->vci_mask & id->vci))
		return -EINVAL;

	if (!try_module_get(adev->ops->owner))
		return -ENODEV;

	/* ok, create vcc */
	vcc = kzalloc(sizeof (*vcc), GFP_KERNEL);
	if (!vcc)
		return -ENOMEM;

	spin_lock_init(&vcc->user_ops_lock);
	spin_lock_init(&vcc->tx_lock);
	vcc->vpi = id->vpi;
	vcc->vci = id->vci;
	vcc->adev = adev;
	vcc->to_drop_pkt = 0;
	memcpy(&vcc->qos, qos, sizeof (*qos));

	ret = adev->ops->open(vcc);
	if (ret) {
		kfree(vcc);
		return ret;
	}

	/* inherit vcc link state from device */
	if (test_bit(FBXATM_DEV_F_LINK_UP, &adev->dev_flags))
		set_bit(FBXATM_VCC_F_LINK_UP, &vcc->vcc_flags);

	list_add_tail(&vcc->next, &adev->vcc_list);
	return ret;
}

/*
 * find device & open vcc on it
 */
static int fbxatm_dev_open_vcc(const struct fbxatm_vcc_id *id,
			       const struct fbxatm_vcc_qos *qos)
{
	int ret;

	mutex_lock(&fbxatm_mutex);
	ret = __fbxatm_dev_open_vcc(id, qos);
	mutex_unlock(&fbxatm_mutex);
	return ret;
}

/*
 * close vcc on device
 */
static int __fbxatm_dev_close_vcc(struct fbxatm_vcc *vcc)
{
	struct fbxatm_dev *adev;

	if (vcc->user != FBXATM_VCC_USER_NONE)
		return -EBUSY;
	adev = vcc->adev;
	module_put(adev->ops->owner);
	adev->ops->close(vcc);
	list_del(&vcc->next);
	kfree(vcc);
	return 0;
}

/*
 * find device & vcc and close it
 */
static int fbxatm_dev_close_vcc(const struct fbxatm_vcc_id *id)
{
	struct fbxatm_vcc *vcc;
	int ret;

	mutex_lock(&fbxatm_mutex);
	vcc = __fbxatm_vcc_get_by_id(id);
	if (IS_ERR(vcc))
		ret = PTR_ERR(vcc);
	else
		ret = __fbxatm_dev_close_vcc(vcc);
	mutex_unlock(&fbxatm_mutex);
	return ret;
}

/*
 * ioctl handler
 */
static int fbxatm_vcc_ioctl(struct socket *sock,
			    unsigned int cmd, void __user *useraddr)
{
	int ret;

	ret = 0;

	switch (cmd) {
	case FBXATM_IOCADD:
	case FBXATM_IOCDEL:
	{
		struct fbxatm_vcc_params params;

		if (copy_from_user(&params, useraddr, sizeof(params)))
			return -EFAULT;

		if (cmd == FBXATM_IOCADD)
			ret = fbxatm_dev_open_vcc(&params.id, &params.qos);
		else
			ret = fbxatm_dev_close_vcc(&params.id);
		break;
	}

	case FBXATM_IOCGET:
	{
		struct fbxatm_vcc_params params;
		struct fbxatm_vcc *vcc;

		if (copy_from_user(&params, useraddr, sizeof(params)))
			return -EFAULT;

		mutex_lock(&fbxatm_mutex);
		vcc = __fbxatm_vcc_get_by_id(&params.id);
		if (IS_ERR(vcc))
			ret = PTR_ERR(vcc);
		else {
			memcpy(&params.qos, &vcc->qos, sizeof (vcc->qos));
			params.user = vcc->user;
		}
		mutex_unlock(&fbxatm_mutex);

		if (ret)
			return ret;

		if (copy_to_user(useraddr, &params, sizeof(params)))
			return -EFAULT;
		break;
	}

	case FBXATM_IOCOAMPING:
	{
		struct fbxatm_oam_ping ping;

		if (copy_from_user(&ping.req, useraddr, sizeof(ping.req)))
			return -EFAULT;

		ret = do_oam_ping(&ping);
		if (ret)
			return ret;

		if (copy_to_user(useraddr, &ping.req, sizeof(ping.req)))
			return -EFAULT;
		break;
	}

	case FBXATM_IOCDROP:
	{
		struct fbxatm_vcc_drop_params params;
		struct fbxatm_vcc *vcc;

		if (copy_from_user(&params, useraddr, sizeof(params)))
			return -EFAULT;

		mutex_lock(&fbxatm_mutex);
		vcc = __fbxatm_vcc_get_by_id(&params.id);
		if (IS_ERR(vcc))
			ret = PTR_ERR(vcc);
		else {
			spin_lock_bh(&vcc->user_ops_lock);
			vcc->to_drop_pkt += params.drop_count;
			spin_unlock_bh(&vcc->user_ops_lock);
			ret = 0;
		}
		mutex_unlock(&fbxatm_mutex);

		if (ret)
			return ret;
		break;
	}

	default:
		return -ENOIOCTLCMD;
	}

	return ret;
}

static struct fbxatm_ioctl fbxatm_vcc_ioctl_ops = {
	.handler	= fbxatm_vcc_ioctl,
	.owner		= THIS_MODULE,
};

int __init fbxatm_vcc_init(void)
{
	fbxatm_register_ioctl(&fbxatm_vcc_ioctl_ops);
	return 0;
}

void fbxatm_vcc_exit(void)
{
	fbxatm_unregister_ioctl(&fbxatm_vcc_ioctl_ops);
}
