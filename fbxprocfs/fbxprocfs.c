/*
 * Freebox ProcFs interface
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/sizes.h>

#include <linux/fbxprocfs.h>

#define PFX	"fbxprocfs: "


static struct list_head clients;
static struct mutex clients_mutex;

static struct proc_dir_entry *root;

/*
 * register  a  fbxprocfs client  with  given  dirname, caller  should
 * consider returned struct opaque
 */
struct fbxprocfs_client *fbxprocfs_add_client(const char *dirname,
					      struct module *owner)
{
	struct fbxprocfs_client *ret, *p;

	ret = NULL;
	mutex_lock(&clients_mutex);

	/* check for duplicate */
	list_for_each_entry(p, &clients, list) {
		if (!strcmp(dirname, p->dirname))
			goto out;
	}

	if (!(ret = kmalloc(sizeof (*ret), GFP_KERNEL))) {
		printk(KERN_ERR PFX "kmalloc failed\n");
		goto out;
	}

	/* try to create client directory */
	if (!(ret->dir = proc_mkdir(dirname, root))) {
		printk(KERN_ERR PFX "can't create %s dir\n", dirname);
		kfree(ret);
		ret = NULL;
		goto out;
	}

	atomic_set(&ret->refcount, 1);
	ret->dirname = dirname;
	list_add(&ret->list, &clients);

out:
	mutex_unlock(&clients_mutex);
	return ret;
}

/*
 * unregister  a  fbxprocfs client, make sure usage count is zero
 */
int fbxprocfs_remove_client(struct fbxprocfs_client *client)
{
	int ret;

	mutex_lock(&clients_mutex);

	ret = 0;
	if (atomic_read(&client->refcount) > 1) {
		ret = -EBUSY;
		goto out;
	}

	remove_proc_entry(client->dirname, root);
	list_del(&client->list);
	kfree(client);

out:
	mutex_unlock(&clients_mutex);
	return ret;
}

/*
 * remove given entries from client directory
 */
static int
__remove_entries(struct fbxprocfs_client *client,
		 const struct fbxprocfs_desc *ro_desc,
		 const struct fbxprocfs_desc *rw_desc)
{
	int i;

	for (i = 0; ro_desc && ro_desc[i].name; i++) {
		remove_proc_entry(ro_desc[i].name, client->dir);
		atomic_dec(&client->refcount);
	}

	for (i = 0; rw_desc && rw_desc[i].name; i++) {
		remove_proc_entry(rw_desc[i].name, client->dir);
		atomic_dec(&client->refcount);
	}

	return 0;
}

/*
 * replacement for NULL rfunc.
 */
static int bad_rfunc(struct seq_file *m, void *ptr)
{
	return -EACCES;
}

/*
 * fbxprocfs write path is now handled by seq_file code. this
 * simplifies client code greatly.
 */
static int fbxprocfs_open(struct inode *inode, struct file *file)
{
	const struct fbxprocfs_desc *desc = PDE_DATA(inode);

	return single_open(file, desc->rfunc ? desc->rfunc : bad_rfunc,
			   (void*)desc->id);
}

/*
 * no particular help from kernel in the write path, fetch user buffer
 * in a kernel buffer and call write func.
 */
static int fbxprocfs_write(struct file *file, const char __user *ubuf,
			   size_t len, loff_t *off)
{
	/*
	 * get fbxprocfs desc via the proc_dir_entry in file inode
	 */
	struct fbxprocfs_desc *d = PDE_DATA(file_inode(file));
	char *kbuf;
	int ret;

	/*
	 * must have a wfunc callback.
	 */
	if (!d->wfunc)
		return -EACCES;

	/*
	 * allow up to SZ_4K bytes to be written.
	 */
	if (len > SZ_4K)
		return -EOVERFLOW;

	/*
	 * alloc and fetch kernel buffer containing user data.
	 */
	kbuf = kmalloc(SZ_4K, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	ret = -EFAULT;
	if (copy_from_user(kbuf, ubuf, len))
		goto kfree;

	ret = d->wfunc(file, kbuf, len, (void*)d->id);

kfree:
	kfree(kbuf);
	return ret;
}

/*
 * fbxprocfs file operations, read stuff is handled by seq_file code.
 */
static const struct file_operations fbxprocfs_fops = {
	.open		= fbxprocfs_open,
	.llseek		= seq_lseek,
	.read		= seq_read,
	.release	= seq_release,
	.write		= fbxprocfs_write,
};

/*
 * replaces create_proc_read_entry removed in latest kernels.
 */
static struct proc_dir_entry *__create_proc_read_entry(
				       const struct fbxprocfs_desc *desc,
				       struct proc_dir_entry *base)
{
	return proc_create_data(desc->name, 0, base, &fbxprocfs_fops,
				(void*)desc);
}

/*
 * replaces create_proc_entry removed in latest kernels.
 */
static struct proc_dir_entry *__create_proc_entry(
					const struct fbxprocfs_desc *desc,
					struct proc_dir_entry *base)
{
	return proc_create_data(desc->name, S_IFREG | S_IWUSR | S_IRUGO,
				base, &fbxprocfs_fops, (void*)desc);
}

/*
 * create given entries in client directory
 */
static int
__create_entries(struct fbxprocfs_client *client,
		 const struct fbxprocfs_desc *ro_desc,
		 const struct fbxprocfs_desc *rw_desc)
{
	struct proc_dir_entry	*proc;
	int			i;

	for (i = 0; ro_desc && ro_desc[i].name; i++) {
		if (!(proc = __create_proc_read_entry(&ro_desc[i],
						      client->dir))) {
			printk(KERN_ERR PFX "can't create %s/%s entry\n",
			       client->dirname, ro_desc[i].name);
			goto err;
		}
		atomic_inc(&client->refcount);
	}

	for (i = 0; rw_desc && rw_desc[i].name; i++) {
		if (!(proc = __create_proc_entry(&rw_desc[i], client->dir))) {
			printk(KERN_ERR PFX "can't create %s/%s entry\n",
			       client->dirname, ro_desc[i].name);
			goto err;
		}
		atomic_inc(&client->refcount);
	}

	return 0;

err:
	__remove_entries(client, ro_desc, rw_desc);
	return -1;
}

int
fbxprocfs_create_entries(struct fbxprocfs_client *client,
			 const struct fbxprocfs_desc *ro_desc,
			 const struct fbxprocfs_desc *rw_desc)
{
	int	ret;

	ret = __create_entries(client, ro_desc, rw_desc);
	return ret;
}

int
fbxprocfs_remove_entries(struct fbxprocfs_client *client,
			 const struct fbxprocfs_desc *ro_desc,
			 const struct fbxprocfs_desc *rw_desc)
{
	int	ret;

	ret = __remove_entries(client, ro_desc, rw_desc);
	return ret;
}


static int __init
fbxprocfs_init(void)
{
	INIT_LIST_HEAD(&clients);
	mutex_init(&clients_mutex);

	/* create freebox directory */
	if (!(root = proc_mkdir("freebox", NULL))) {
		printk(KERN_ERR PFX "can't create freebox/ dir\n");
		return -EIO;
	}
	return 0;
}

static void __exit
fbxprocfs_exit(void)
{
	remove_proc_entry("freebox", NULL);
}

module_init(fbxprocfs_init);
module_exit(fbxprocfs_exit);

EXPORT_SYMBOL(fbxprocfs_create_entries);
EXPORT_SYMBOL(fbxprocfs_remove_entries);
EXPORT_SYMBOL(fbxprocfs_add_client);
EXPORT_SYMBOL(fbxprocfs_remove_client);

MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");
MODULE_AUTHOR("Maxime Bizon <mbizon@freebox.fr>");

