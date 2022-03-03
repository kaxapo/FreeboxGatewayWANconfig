#ifndef FBXPROCFS_H_
#define FBXPROCFS_H_

#include <linux/proc_fs.h>
#include <asm/atomic.h>
#include <linux/seq_file.h>

struct fbxprocfs_client
{
	const char *dirname;
	struct module *owner;
	struct proc_dir_entry *dir;
	atomic_t refcount;
	struct list_head list;
};

struct fbxprocfs_desc {
	char		*name;
	unsigned long	id;
	int	(*rfunc)(struct seq_file *, void *);
	int	(*wfunc)(struct file *, const char *, unsigned long, void *);
};

struct fbxprocfs_client *fbxprocfs_add_client(const char *dirname,
					      struct module *owner);

int fbxprocfs_remove_client(struct fbxprocfs_client *client);


int
fbxprocfs_create_entries(struct fbxprocfs_client *client,
			 const struct fbxprocfs_desc *ro_desc,
			 const struct fbxprocfs_desc *rw_desc);

int
fbxprocfs_remove_entries(struct fbxprocfs_client *client,
			 const struct fbxprocfs_desc *ro_desc,
			 const struct fbxprocfs_desc *rw_desc);

#endif /* FBXPROCFS_H_ */
