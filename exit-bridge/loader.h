#ifndef A7_LATE_EXIT_LOADER_H
#define A7_LATE_EXIT_LOADER_H
#include "../startup-owner/platform/platform.h"
struct late_status {uint32_t stage,error,pins,armed;};
/* No feature resources may be constructed before this returns zero. */
int late_open(struct np_context*);
const struct late_status*late_report(void);
#endif
