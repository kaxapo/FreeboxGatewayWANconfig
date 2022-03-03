/*
 * fbxgw-pcie.h for fbxgw
 * Created by <nschichan@freebox.fr> on Tue Jan 27 15:39:48 2015
 */

#ifndef __FBXGW_PCIE_H
# define __FBXGW_PCIE_H

struct fbxgw_pcie_priv;

int fbxgw_pcie_preinit(struct fbxgw_pcie_priv **p);
int fbxgw_pcie_retrain_link(struct fbxgw_pcie_priv *p);
int fbxgw_pcie_preexit(struct fbxgw_pcie_priv *p);

#endif /* !__FBXGW_PCIE_H */
