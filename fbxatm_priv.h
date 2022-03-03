#ifndef FBXATM_PRIV_H_
#define FBXATM_PRIV_H_

#include <linux/list.h>
#include <linux/mutex.h>

extern struct list_head fbxatm_dev_list;
extern struct mutex fbxatm_mutex;

int __init fbxatm_vcc_init(void);

void fbxatm_vcc_exit(void);

void __fbxatm_free_device(struct fbxatm_dev *adev);

int __init fbxatm_2684_init(void);

void fbxatm_2684_exit(void);

/*
 * pppoa
 */
#ifdef CONFIG_PPP
int __init fbxatm_pppoa_init(void);

void fbxatm_pppoa_exit(void);
#else
static inline int fbxatm_pppoa_init(void) { return 0; };
static inline void fbxatm_pppoa_exit(void) { };
#endif

/*
 * procfs stuff
 */
int fbxatm_proc_dev_register(struct fbxatm_dev *dev);

void fbxatm_proc_dev_deregister(struct fbxatm_dev *dev);

struct proc_dir_entry *fbxatm_proc_misc_register(const char *path);

void fbxatm_proc_misc_deregister(const char *path);

int __init fbxatm_procfs_init(void);

void fbxatm_procfs_exit(void);


/*
 * sysfs stuff
 */
int __init fbxatm_sysfs_init(void);

void fbxatm_sysfs_exit(void);

void fbxatm_dev_change_sysfs(struct fbxatm_dev *adev);

int fbxatm_register_dev_sysfs(struct fbxatm_dev *adev);

void fbxatm_unregister_dev_sysfs(struct fbxatm_dev *adev);


/*
 * crc10
 */
u16 crc10(u16 crc, const u8 *buffer, size_t len);

#endif /* !FBXATM_PRIV_H_ */
