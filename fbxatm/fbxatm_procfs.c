#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/fbxatm_dev.h>
#include <net/net_namespace.h>
#include "fbxatm_priv.h"

static struct proc_dir_entry *fbxatm_proc_root;

/*
 * /proc/net/atm/vcc
 */
static int vcc_seq_show(struct seq_file *seq, void *v)
{
	struct fbxatm_vcc *vcc;

	if (v == (void *)SEQ_START_TOKEN) {
		seq_printf(seq, "%s",
			   "Itf.VPI.VCI USER TC MaxSDU  RX TX  RXAAL5 "
			   "TXAAL5\n");
		return 0;
	}

	vcc = (struct fbxatm_vcc *)v;
	seq_printf(seq, "%d.%u.%u %d ", vcc->adev->ifindex,
		   vcc->vpi, vcc->vci, vcc->user);
	seq_printf(seq, "%u %u ", vcc->qos.traffic_class, vcc->qos.max_sdu);
	seq_printf(seq, "%lu %lu  %lu %lu\n",
		   vcc->stats.rx_bytes,
		   vcc->stats.tx_bytes,
		   vcc->stats.rx_aal5,
		   vcc->stats.tx_aal5);
	return 0;
}

static void *vcc_seq_start(struct seq_file *seq, loff_t *pos)
{
	struct fbxatm_dev *adev;
	struct fbxatm_vcc *tvcc, *vcc;
	int count;

	mutex_lock(&fbxatm_mutex);

	if (!*pos)
		return SEQ_START_TOKEN;

	count = 1;
	tvcc = NULL;
	list_for_each_entry(adev, &fbxatm_dev_list, next) {
		list_for_each_entry(vcc, &adev->vcc_list, next) {
			if (count == *pos) {
				tvcc = vcc;
				break;
			}
			count++;
		}
	}

	return tvcc;
}

static void *vcc_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct fbxatm_dev *adev;
	struct fbxatm_vcc *last_vcc, *vcc, *tvcc;

	if (v == (void *)SEQ_START_TOKEN) {
		if (list_empty(&fbxatm_dev_list))
			return NULL;
		adev = list_entry(fbxatm_dev_list.next, struct fbxatm_dev,
				  next);
		last_vcc = NULL;
	} else {
		last_vcc = (struct fbxatm_vcc *)v;
		adev = last_vcc->adev;
	}

	tvcc = NULL;
	list_for_each_entry_continue(adev, &fbxatm_dev_list, next) {

		if (last_vcc && last_vcc->adev == adev) {
			vcc = last_vcc;
			list_for_each_entry_continue(vcc, &adev->vcc_list,
						     next) {
				tvcc = vcc;
				break;
			}
		} else {
			list_for_each_entry(vcc, &adev->vcc_list, next) {
				tvcc = vcc;
				break;
			}
		}
	}

	if (tvcc)
		(*pos)++;
	return tvcc;
}

static void vcc_seq_stop(struct seq_file *seq, void *v)
{
	mutex_unlock(&fbxatm_mutex);
}

static const struct seq_operations vcc_seq_ops = {
	.start		= vcc_seq_start,
	.next		= vcc_seq_next,
	.stop		= vcc_seq_stop,
	.show		= vcc_seq_show,
};

static int vcc_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &vcc_seq_ops);
}

static const struct file_operations vcc_seq_fops = {
	.open		= vcc_seq_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

/*
 * /proc/net/atm/dev
 */
static int adev_seq_show(struct seq_file *seq, void *v)
{
	struct fbxatm_dev *adev;

	if (v == (void *)SEQ_START_TOKEN) {
		seq_printf(seq, "%s",
			   "Itf  RX TX  RXAAL5 TXAAL5  RXF4OAM TXF4OAM  "
			   "RXF5OAM TXF5OAM  RXBADOAM RXBADLLIDOAM "
			   "RXOTHEROAM RXDROPPED TXDROPNOLINK\n");
		return 0;
	}

	adev = (struct fbxatm_dev *)v;
	seq_printf(seq, "%d  %lu %lu  %lu %lu  ",
		   adev->ifindex,
		   adev->stats.rx_bytes,
		   adev->stats.tx_bytes,
		   adev->stats.rx_aal5,
		   adev->stats.tx_aal5);

	seq_printf(seq, "%lu %lu  %lu %lu  %lu %lu %lu %lu %lu\n",
		   adev->stats.rx_f4_oam,
		   adev->stats.tx_f4_oam,

		   adev->stats.rx_f5_oam,
		   adev->stats.tx_f5_oam,

		   adev->stats.rx_bad_oam,
		   adev->stats.rx_bad_llid_oam,
		   adev->stats.rx_other_oam,
		   adev->stats.rx_dropped,
		   adev->stats.tx_drop_nolink);
	return 0;
}

static void *adev_seq_start(struct seq_file *seq, loff_t *pos)
{
	struct fbxatm_dev *adev, *tadev;
	int count;

	mutex_lock(&fbxatm_mutex);

	if (!*pos)
		return SEQ_START_TOKEN;

	count = 1;
	tadev = NULL;
	list_for_each_entry(adev, &fbxatm_dev_list, next) {
		if (count == *pos) {
			tadev = adev;
			break;
		}
		count++;
	}

	return tadev;
}

static void *adev_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct fbxatm_dev *adev, *tadev;

	if (v == (void *)SEQ_START_TOKEN) {
		if (list_empty(&fbxatm_dev_list))
			return NULL;
		adev = list_entry(fbxatm_dev_list.next, struct fbxatm_dev,
				  next);
	} else
		adev = (struct fbxatm_dev *)v;

	tadev = NULL;
	list_for_each_entry_continue(adev, &fbxatm_dev_list, next) {
		tadev = adev;
		break;
	}

	if (tadev)
		(*pos)++;
	return tadev;
}

static void adev_seq_stop(struct seq_file *seq, void *v)
{
	mutex_unlock(&fbxatm_mutex);
}

static const struct seq_operations adev_seq_ops = {
	.start		= adev_seq_start,
	.next		= adev_seq_next,
	.stop		= adev_seq_stop,
	.show		= adev_seq_show,
};

static int adev_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &adev_seq_ops);
}

static const struct file_operations adev_seq_fops = {
	.open		= adev_seq_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};


/*
 * create device private entry in proc
 */
int fbxatm_proc_dev_register(struct fbxatm_dev *adev)
{
	adev->dev_proc_entry = proc_mkdir(adev->name, fbxatm_proc_root);
	if (!adev->dev_proc_entry)
		return 1;
	return 0;
}


void fbxatm_proc_dev_deregister(struct fbxatm_dev *adev)
{
	remove_proc_entry(adev->name, fbxatm_proc_root);
}

/*
 * create misc private entry in proc
 */
struct proc_dir_entry *fbxatm_proc_misc_register(const char *path)
{
	return proc_mkdir(path, fbxatm_proc_root);
}

void fbxatm_proc_misc_deregister(const char *path)
{
	remove_proc_entry(path, fbxatm_proc_root);
}

/*
 * list of proc entries for fbxatm
 */
static struct fbxatm_proc_entry {
	char *name;
	const struct file_operations *proc_fops;
	struct proc_dir_entry *dirent;

} fbxatm_proc_entries[] = {
	{
		.name = "dev",
		.proc_fops = &adev_seq_fops,
	},
	{
		.name = "vcc",
		.proc_fops = &vcc_seq_fops,
	},
};

static void fbxatm_remove_proc(void)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(fbxatm_proc_entries); i++) {
		struct fbxatm_proc_entry *e;

		e = &fbxatm_proc_entries[i];

		if (!e->dirent)
			continue;
		remove_proc_entry(e->name, fbxatm_proc_root);
		e->dirent = NULL;
	}

	remove_proc_entry("fbxatm", init_net.proc_net);
}

int __init fbxatm_procfs_init(void)
{
	unsigned int i;
	int ret;

	fbxatm_proc_root = proc_net_mkdir(&init_net, "fbxatm",
					  init_net.proc_net);
	if (!fbxatm_proc_root) {
		ret = -ENOMEM;
		goto err;
	}

	for (i = 0; i < ARRAY_SIZE(fbxatm_proc_entries); i++) {
		struct proc_dir_entry *dirent;
		struct fbxatm_proc_entry *e;

		e = &fbxatm_proc_entries[i];

		dirent = proc_create_data(e->name, S_IRUGO, fbxatm_proc_root,
					  e->proc_fops, NULL);
		if (!dirent) {
			ret = -ENOMEM;
			goto err;
		}
		e->dirent = dirent;
	}

	return 0;

err:
	if (fbxatm_proc_root)
		fbxatm_remove_proc();
	return ret;
}

void fbxatm_procfs_exit(void)
{
	fbxatm_remove_proc();
}
