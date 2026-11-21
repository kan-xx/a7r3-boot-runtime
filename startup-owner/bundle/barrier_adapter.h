#ifndef FB_BARRIER_ADAPTER_H
#define FB_BARRIER_ADAPTER_H
#include "../barrier/ports.h"
struct fb_barrier_status {uint32_t initialized,warmup_attempted,warmup_result,runs;struct bp_report warmup;};
int fb_barrier_init(struct np_context*);
int fb_barrier_run(void*,struct bp_report*);
const struct fb_barrier_status*fb_barrier_status(void);
#endif
