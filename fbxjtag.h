#ifndef FBXJTAG_H_
# define FBXJTAG_H_

#ifdef __KERNEL__
# include <linux/types.h>
#endif

# define JTAG_RESET_STEPS	16
# define JTAG_DATA_READ_SIZE	128
# define JTAG_INST_READ_SIZE	128
# define JTAG_DEF_CLOCK_DELAY	500
# define JTAG_DEF_WAIT_TMS	0

enum jtag_main_state {
	JTAG_STATE_TEST_MASK	=	0x10,
	JTAG_STATE_RUN_MASK	=	0x20,
	JTAG_STATE_DR_MASK	=	0x40,
	JTAG_STATE_IR_MASK	=	0x80,
};
#define JTAG_STATE_MASK			0xF0

enum jtag_sub_state {
	JTAG_SUB_STATE_SELECT	=	0x0,
	JTAG_SUB_STATE_CAPTURE	=	0x1,
	JTAG_SUB_STATE_SHIFT	=	0x2,
	JTAG_SUB_STATE_EXIT1	=	0x3,
	JTAG_SUB_STATE_PAUSE	=	0x4,
	JTAG_SUB_STATE_EXIT2	=	0x5,
	JTAG_SUB_STATE_UPDATE	=	0x6,
};
#define JTAG_SUB_STATE_MASK		0xF

enum jtag_state {
	JTAG_STATE_UNDEF	= 0,
	JTAG_STATE_TEST_LOGIC_RESET	= JTAG_STATE_TEST_MASK,
	JTAG_STATE_RUN_TEST_IDLE	= JTAG_STATE_RUN_MASK,

	JTAG_STATE_SELECT_DR	= JTAG_STATE_DR_MASK | JTAG_SUB_STATE_SELECT,
	JTAG_STATE_CAPTURE_DR	= JTAG_STATE_DR_MASK | JTAG_SUB_STATE_CAPTURE,
	JTAG_STATE_SHIFT_DR	= JTAG_STATE_DR_MASK | JTAG_SUB_STATE_SHIFT,
	JTAG_STATE_EXIT1_DR	= JTAG_STATE_DR_MASK | JTAG_SUB_STATE_EXIT1,
	JTAG_STATE_PAUSE_DR	= JTAG_STATE_DR_MASK | JTAG_SUB_STATE_PAUSE,
	JTAG_STATE_EXIT2_DR	= JTAG_STATE_DR_MASK | JTAG_SUB_STATE_EXIT2,
	JTAG_STATE_UPDATE_DR	= JTAG_STATE_DR_MASK | JTAG_SUB_STATE_UPDATE,

	JTAG_STATE_SELECT_IR	= JTAG_STATE_IR_MASK | JTAG_SUB_STATE_SELECT,
	JTAG_STATE_CAPTURE_IR	= JTAG_STATE_IR_MASK | JTAG_SUB_STATE_CAPTURE,
	JTAG_STATE_SHIFT_IR	= JTAG_STATE_IR_MASK | JTAG_SUB_STATE_SHIFT,
	JTAG_STATE_EXIT1_IR	= JTAG_STATE_IR_MASK | JTAG_SUB_STATE_EXIT1,
	JTAG_STATE_PAUSE_IR	= JTAG_STATE_IR_MASK | JTAG_SUB_STATE_PAUSE,
	JTAG_STATE_EXIT2_IR	= JTAG_STATE_IR_MASK | JTAG_SUB_STATE_EXIT2,
	JTAG_STATE_UPDATE_IR	= JTAG_STATE_IR_MASK | JTAG_SUB_STATE_UPDATE,

	JTAG_STATE_MAX
};

#define JTAG_STATE_IN_DR(state)	((state) & JTAG_STATE_DR_MASK)
#define JTAG_STATE_IN_IR(state)	((state) & JTAG_STATE_IR_MASK)

#ifdef __KERNEL__

#define JTAG_BUF_SIZE	2048

struct fbxjtag_data {
	const char	*name;
	struct {
		struct fbxgpio_pin	*tck;
		struct fbxgpio_pin	*tms;
		struct fbxgpio_pin	*tdi;
		struct fbxgpio_pin	*tdo;
	}		gpios;
	unsigned long	clock_delay;
	unsigned long	wait_tms;
	unsigned long	data_read_size;
	unsigned long	instruction_read_size;
	struct device	*dev;
	enum jtag_state state;
	char		nb_reset;
	char		dr_buf[JTAG_BUF_SIZE];
	unsigned 	dr_w;
	unsigned 	dr_r;
	char		ir_buf[JTAG_BUF_SIZE];
	unsigned 	ir_r;
	unsigned 	ir_w;
};
#endif

#endif /* !FBXJTAG_H_ */
