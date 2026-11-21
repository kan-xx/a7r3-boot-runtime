#ifndef A7_LIFECYCLE_COMPLETION_OWNER_H
#define A7_LIFECYCLE_COMPLETION_OWNER_H
#include "menu_power.h"
#include "probe.h"
#define LO_BUILD 0x3110cc0eu
#define LO_AUDIO_BUILD 0x3110d10cu
#define LO_MENU_BUILD 0x3110d015u
/* One original IM callback thread, one worker. Binding, immutable-code checks,
 * self/provider pins, scheduling and snapshot locking belong to the native
 * wrapper. This core cannot be installed as an IM module on its own. */
enum {LO_INIT=1,LO_INACT,LO_SUS,LO_RES,LO_ACT,LO_EXIT};
enum {LO_OK,LO_PENDING,LO_ALREADY,LO_INVALID,LO_ERROR};
struct lo_im_state {uint32_t pid,descriptor,module_id,type,state,pending;};
struct lo_ports {
 void*context;uint32_t(*tid)(void*);
 int(*native_state)(void*,uint32_t,struct lo_im_state*);
 int(*completion)(void*,uint32_t,uint32_t);
 int(*barrier)(void*,struct bp_report*);
};
struct lo_config {
 struct lo_ports port;const struct ap_power_api*audio;const struct mp_power_api*menu;
 uint32_t pid,im_tid,worker_tid,descriptor;uint8_t audio_id[16],menu_id[16];
};
struct lo_status {
 uint32_t abi,bytes,build,event,generation,error,audio_epoch,menu_epoch,proof_generation,inact_claim,act_claim;
 uint32_t audio_pause_result,menu_pause_result,audio_resume_result,menu_resume_result;
 uint32_t worker_generation,started_ms,barrier_attempt_epoch,barrier_verified_epoch,inact_sends,act_sends,exit_drained;
 uint32_t bootstrap_state,bootstrap_barrier,bootstrap_audio_result,bootstrap_menu_result;
 struct lp_status audio;struct mp_power_report menu;struct bp_report barrier;
};
struct lo_control {
 struct lo_config cfg;uint32_t initialized,request,error,audio_epoch,menu_epoch,proof_generation,inact_claim,act_claim;
 uint32_t audio_pause_result,menu_pause_result,audio_resume_result,menu_resume_result;
 struct lo_status status;uint32_t barrier_pending_epoch,worker_event,handoff_sealed;uint32_t bootstrap_state;
};
#define LO_EXPORT __attribute__((visibility("default")))
LO_EXPORT uint32_t lo_size(void);
LO_EXPORT int lo_init(struct lo_control*,const struct lo_config*);
/* The six native callbacks forward here. INIT has no resource/start side
 * effects. INACT/EXIT revoke immediately; ACT alone may authorize resume. */
/* Worker-only, before callback handoff. Both providers must be constructed
 * with admission already paused at epoch1; this call grants no activity. */
LO_EXPORT int lo_bootstrap_arm(struct lo_control*);
LO_EXPORT int lo_event(struct lo_control*,uint32_t);
/* Bootstrap worker may adopt the latest early INIT / initial ACT / INACT
 * before the wrapper atomically publishes READY. No resume or ACK occurs.
 * Any normal event/tick seals adoption permanently. Never call concurrently
 * with normal events/ticks; the wrapper's CAS publication enforces this. */
LO_EXPORT int lo_adopt(struct lo_control*,uint32_t packed_request);
/* Config must already be release-published. Revoke only, any callback thread. */
LO_EXPORT int lo_close(struct lo_control*);
/* Unexpected cross-thread Exit is terminal: close and retain all resources. */
LO_EXPORT int lo_abort(struct lo_control*);
LO_EXPORT int lo_tick(struct lo_control*,uint32_t);
/* Worker-only coherent report. Native host status needs a separate cache. */
LO_EXPORT int lo_report(const struct lo_control*,struct lo_status*);
#endif
