#ifndef A7_LIFECYCLE_INGRESS_H
#define A7_LIFECYCLE_INGRESS_H
#include "../lifecycle/owner.h"
#define LW_BUILD 0x3010cc41u
#define LW_READY 0x80000000u
struct lw_control {
 uint32_t mailbox,error,prepared,prepare_claim,init_tid,main_tid,exit_tid;
 struct lo_control owner;
};
struct lw_status {uint32_t abi,bytes,build,mailbox,error,prepared,init_tid,main_tid,exit_tid,owner_error;};
/* Init only records an early event. A separate authenticated native bootstrap
 * must schedule the worker, retain self/providers and canonical registration,
 * and call prepare after provider identity/pinning is complete. No bootstrap
 * or camera deployment is supplied by this ingress library. Early INACT is
 * retained without ACK until the owner can prove provider drain. */
LO_EXPORT uint32_t lw_size(void);
LO_EXPORT int lw_event(struct lw_control*,uint32_t event,uint32_t caller_tid);
LO_EXPORT int lw_prepare(struct lw_control*,const struct lo_config*);
LO_EXPORT int lw_tick(struct lw_control*,uint32_t now);
LO_EXPORT int lw_report(const struct lw_control*,struct lw_status*);
#endif
