#ifndef A7R_TOUCH_OWNER_GATE_H
#define A7R_TOUCH_OWNER_GATE_H
#include "../lifecycle/owner.h"
struct touch_owner_now {
 uint32_t request,phase,ready,stop,error,final_requested,ingress_error,
          prepared,owner_error,bootstrap_error,bootstrap_ready,
          bootstrap_state,act_claim,ui_tid;
};
_Static_assert(sizeof(struct touch_owner_now)==56,"No snapshot padding");
/* Existing owner worker only. The two snapshots surround its original
 * lo_report; this is optional loading admission, never an ACK or provider grant.
 */
int touch_owner_gate(const struct touch_owner_now *,const struct touch_owner_now *,
                     const struct lo_status *);
#endif
