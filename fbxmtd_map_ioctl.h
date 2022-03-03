/*
 * fbxmtd_map_ioctl.h for linux-freebox
 * Created by <nschichan@freebox.fr> on Thu Feb  8 20:37:28 2007
 * Freebox SA
 */

#ifndef FBXMTD_MAP_IOCTL_H
# define FBXMTD_MAP_IOCTL_H

/*
 * IOCTL interface
 */
#define FBXMTD_MINOR	242

#define FBXMTD_MAP_IOCTL_MAX_DEV	2
#define FBXMTD_MAP_IOCTL_MAX_PART	16

struct fbxmtd_map_ioctl_part
{
	char		name[32];
	uint32_t	offset;
	uint32_t	size;
	uint32_t	flags;
};

struct fbxmtd_map_ioctl_dev
{
	char				name[32];
	uint32_t			base_phys;
	int				bus_width;
	uint32_t			size;
	uint32_t			status;
	struct fbxmtd_map_ioctl_part	parts[FBXMTD_MAP_IOCTL_MAX_PART];
	int				num_parts;
};

#define FBXMTD_MAP_IOCTL_NR	0x42

struct fbxmtd_map_ioctl_query
{
	uint32_t	cmd;
	uint32_t	param;
	int		result;
	void __user	*user_buf;
	uint32_t	user_buf_size;
};

#define FBXMTDCTL_CMD_GET_DEVICES	0x1
#define FBXMTDCTL_CMD_ADD_DEVICE	0x2
#define FBXMTDCTL_CMD_DEL_DEVICE	0x3

#endif /* !FBXMTD_MAP_IOCTL_H */
