#ifndef A7_NATIVE_FEATURE_BUNDLE_H
#define A7_NATIVE_FEATURE_BUNDLE_H
#include "../platform/platform.h"
#include "../bootstrap/bootstrap_gate.h"
#include "../include/audio/runtime_abi.h"
#include "../include/audio/resource_diag.h"
#include "../include/sd_refresh/runtime_abi.h"
#include "../include/observer/observer_f7_abi.h"
/* Two historical component headers used the same private enum name.
 * Rename only its spelling in this integration translation unit; no ABI changes. */
#define MP_REFRESH FB_MENU_REFRESH
#include "../include/menu/product.h"
#undef MP_REFRESH
struct fb_status {uint32_t abi,bytes,stage,error,provider,pins,accepted,last_rc,ui_tid,ui_start,ui_base,ui_manager,source_stopped,audio_stopped,menu_parked,finish_error,finish_stage,observer_stopped;};
struct fb_context {
 int(*audio_timing)(uint32_t*);uint32_t timing[8];
 struct np_context*platform;void*pins[6];uint32_t bases[6];
 const struct rr_api*source;const f7_api*observer;const struct ap_api*audio;const struct mp_api*menu;
 const struct ap_power_api*audio_power;const struct mp_power_api*menu_power;
 uint8_t identities[5][16];struct fb_status s;
 struct rr_report rr;f7_status f7;struct ap_report ap;struct mp_report mp;
 int(*audio_diagnostic)(struct fr_diagnostic*);struct fr_diagnostic diagnostic;
 int(*audio_certify)(const uint8_t*,const struct bp_report*);int(*audio_domain)(struct fr_domain_record*);struct fr_domain_record domain;
};
/* Worker-only preparation and one adoption sequence. All references remain
 * held after any ambiguity. This component supplies no lifecycle ACK itself. */
int fb_open(struct fb_context*,struct np_context*);
int fb_start(struct fb_context*,struct bg_control*);
int fb_observe(struct fb_context*);
int fb_certified_barrier(void*,struct bp_report*);
/* Process-finalization only, on the native owner worker after a proven LO_EXIT drain; no restart
 * or release of native sound allocations. Caller must join this worker before original provider finalizers and keep original providers
 * alive until this returns. Not yet qualified for deployment. */
int fb_finish(struct fb_context*,const struct lo_status*);
#endif
