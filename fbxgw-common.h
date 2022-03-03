/*
 * fbxgw-common.h for fbxgw
 * Created by <nschichan@freebox.fr> on Mon Jan 26 12:43:05 2015
 */

#ifndef __FBXGW_COMMON_H
# define __FBXGW_COMMON_H

void fbxgw_reserve_crash_zone(void);
void fbxgw_common_nand_init(void);
void fbxgw_common_fixup_i2c(int bus_nr);
void fbxgw_fbxatm_init(void);

#endif /* !__FBXGW_COMMON_H */
