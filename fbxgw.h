#ifdef CONFIG_MACH_FBXGW1R
void fbxgw1r_init(void);
#else
static inline void fbxgw1r_init(void) {};
#endif

#ifdef CONFIG_MACH_FBXGW2R
void fbxgw2r_init(void);
#else
static inline void fbxgw2r_init(void) {};
#endif
