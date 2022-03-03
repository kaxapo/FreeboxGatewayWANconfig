/*
 * fbxgpio.h for linux-freebox
 * Created by <nschichan@freebox.fr> on Wed Feb 21 22:09:46 2007
 * Freebox SA
 */

#ifndef FBXGPIO_H
# define FBXGPIO_H

# include <linux/types.h>

/* can change pin direction */
#define FBXGPIO_PIN_DIR_RW	(1 << 0)
#define FBXGPIO_PIN_REVERSE_POL	(1 << 1)

struct fbxgpio_operations {
	int  (*get_datain)(int gpio);
	void (*set_dataout)(int gpio, int val);
	int  (*get_dataout)(int gpio);
	void (*set_direction)(int gpio, int dir);
	int  (*get_direction)(int gpio);
};


struct fbxgpio_pin {
	const struct fbxgpio_operations	*ops;
	const char			*pin_name;
	uint32_t			flags;
	int				direction;
	int				pin_num;
	unsigned int			cur_dataout;
	struct device			*dev;
};


#define GPIO_DIR_IN	0x1
#define GPIO_DIR_OUT	0x0

#endif /* !FBXGPIO_H */
