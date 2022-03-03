/*
 * Generic fbxatm definition, exported to userspace
 */
#ifndef LINUX_FBXATM_H_
#define LINUX_FBXATM_H_

#include <linux/types.h>
#include <linux/if.h>

#define FBXATM_IOCTL_MAGIC		0xd3

/* allow userspace usage without up to date kernel headers */
#ifndef PF_FBXATM
#define PF_FBXATM			32
#define AF_FBXATM			PF_FBXATM
#endif

struct fbxatm_vcc_id {
	int				dev_idx;
	__u32				vpi;
	__u32				vci;
};

enum fbxatm_vcc_user {
	FBXATM_VCC_USER_NONE = 0,
	FBXATM_VCC_USER_2684,
	FBXATM_VCC_USER_PPPOA,
};

enum fbxatm_vcc_traffic_class {
	FBXATM_VCC_TC_UBR_NO_PCR = 0,
	FBXATM_VCC_TC_UBR,
};

struct fbxatm_vcc_qos {
	__u32				traffic_class;
	__u32				max_sdu;
	__u32				max_buffered_pkt;
	__u32				priority;
	__u32				rx_priority;
};


/*
 * VCC related
 */
struct fbxatm_vcc_params {
	/* ADD/DEL/GET */
	struct fbxatm_vcc_id		id;

	/* ADD/GET */
	struct fbxatm_vcc_qos		qos;

	/* GET */
	enum fbxatm_vcc_user		user;
};

#define FBXATM_IOCADD		_IOW(FBXATM_IOCTL_MAGIC,	1,	\
					struct fbxatm_vcc_params)

#define FBXATM_IOCDEL		_IOR(FBXATM_IOCTL_MAGIC,	2,	\
					struct fbxatm_vcc_params)

#define FBXATM_IOCGET		_IOWR(FBXATM_IOCTL_MAGIC,	3,	\
					struct fbxatm_vcc_params)


struct fbxatm_vcc_drop_params {
	struct fbxatm_vcc_id		id;
	unsigned int			drop_count;
};

#define FBXATM_IOCDROP		_IOWR(FBXATM_IOCTL_MAGIC,	5,	\
					struct fbxatm_vcc_drop_params)

/*
 * OAM related
 */
enum fbxatm_oam_ping_type {
	FBXATM_OAM_PING_SEG_F4	= 0,
	FBXATM_OAM_PING_SEG_F5,
	FBXATM_OAM_PING_E2E_F4,
	FBXATM_OAM_PING_E2E_F5,
};

struct fbxatm_oam_ping_req {
	/* only dev_idx for F4 */
	struct fbxatm_vcc_id		id;

	__u8				llid[16];
	enum fbxatm_oam_ping_type	type;
};

#define FBXATM_IOCOAMPING	_IOWR(FBXATM_IOCTL_MAGIC,	10,	\
				      struct fbxatm_oam_ping_req)


/*
 * PPPOA related
 */
enum fbxatm_pppoa_encap {
	FBXATM_EPPPOA_AUTODETECT = 0,
	FBXATM_EPPPOA_VCMUX,
	FBXATM_EPPPOA_LLC,
};

struct fbxatm_pppoa_vcc_params {
	struct fbxatm_vcc_id		id;
	__u32				encap;
	__u32				cur_encap;
};

#define FBXATM_PPPOA_IOCADD	_IOW(FBXATM_IOCTL_MAGIC,	20,	\
					struct fbxatm_pppoa_vcc_params)

#define FBXATM_PPPOA_IOCDEL	_IOW(FBXATM_IOCTL_MAGIC,	21,	\
					struct fbxatm_pppoa_vcc_params)

#define FBXATM_PPPOA_IOCGET	_IOWR(FBXATM_IOCTL_MAGIC,	22,	\
					struct fbxatm_pppoa_vcc_params)



/*
 * 2684 related
 */
enum fbxatm_2684_encap {
	FBXATM_E2684_VCMUX = 0,
	FBXATM_E2684_LLC,
};

enum fbxatm_2684_payload {
	FBXATM_P2684_BRIDGE = 0,
	FBXATM_P2684_ROUTED,
};

#define FBXATM_2684_MAX_VCC		8

struct fbxatm_2684_vcc_params {
	struct fbxatm_vcc_id		id_list[FBXATM_2684_MAX_VCC];
	size_t				id_count;

	__u32				encap;
	__u32				payload;
	char				dev_name[IFNAMSIZ];
};


#define FBXATM_2684_IOCADD	_IOW(FBXATM_IOCTL_MAGIC,	30,	\
					struct fbxatm_2684_vcc_params)

#define FBXATM_2684_IOCDEL	_IOW(FBXATM_IOCTL_MAGIC,	31,	\
					struct fbxatm_2684_vcc_params)

#define FBXATM_2684_IOCGET	_IOWR(FBXATM_IOCTL_MAGIC,	32,	\
					struct fbxatm_2684_vcc_params)

#endif /* LINUX_FBXATM_H_ */
