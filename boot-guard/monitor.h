#ifndef A7_RUNTIME_RECOVERY_MONITOR_H
#define A7_RUNTIME_RECOVERY_MONITOR_H
#include "transaction.h"
/* An explicit sealed failure for the previously accepted process, not a
 * hang detector. No writes or recovery decisions from an absent record. */
struct gm_monitor {struct gx_record ready;uint32_t armed,error;};
int gm_arm(struct gm_monitor*,int,const struct gx_config*);
/* 0 absent, 1 authenticated explicit failure, -1 malformed/uncertain. */
int gm_poll(const struct gm_monitor*,int,const struct gx_config*,uint32_t*);
int gm_failure_name(char*,unsigned,const char*);
#endif
