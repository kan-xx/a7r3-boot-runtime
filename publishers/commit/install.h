#ifndef A7R_ATOMIC_INSTALL_H
#define A7R_ATOMIC_INSTALL_H
#include "../../boot-guard/transaction.h"
enum {GI_OK=0,GI_INVALID=20,GI_SOURCE=21,GI_MOUNT=22,GI_CHANGED=23,GI_LINK=24,GI_SYNC=25,GI_RENAME=26,GI_READONLY=27,GI_CLOSE=28};
struct gi_result {uint32_t code,verified,linked,renamed,readonly;};
int gi_run(int,const struct gx_config*,const char*,const char*,int,struct gi_result*);
#endif
