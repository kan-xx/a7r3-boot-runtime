#ifndef A7R_FULL_BOOTSTRAP_GATE_H
#define A7R_FULL_BOOTSTRAP_GATE_H
#include "ingress.h"
enum {BG_SOURCE=1,BG_OBSERVER=2,BG_AUDIO=4,BG_MENU=8,BG_ALL=15};
enum {BG_OK,BG_PENDING,BG_REJECT,BG_FAILED};
struct bg_control {struct lw_control ingress;uint32_t begun,accepted,inflight,error,ready;};
/* Configuration pins all API providers before the first resource starts.
 * One worker performs source, observer, audio and menu adoption in order.
 * Native callbacks always enter bg_event, including during construction.
 * There is no zero-resource completion after begin, even on startup error. */
int bg_prepare(struct bg_control*,const struct lo_config*);
int bg_begin(struct bg_control*);
int bg_enter(struct bg_control*,uint32_t);
int bg_adopt(struct bg_control*,uint32_t);
int bg_event(struct bg_control*,uint32_t,uint32_t);
int bg_tick(struct bg_control*,uint32_t);
int bg_fail(struct bg_control*,uint32_t);
#endif
