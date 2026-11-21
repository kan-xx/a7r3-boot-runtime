#include "bootstrap_gate.h"
static uint32_t ld(const uint32_t*p){return __atomic_load_n(p,__ATOMIC_ACQUIRE);}
static void st(uint32_t*p,uint32_t v){__atomic_store_n(p,v,__ATOMIC_RELEASE);}
static int worker(const struct bg_control*c){return c&&ld(&c->ingress.prepared)&&c->ingress.owner.cfg.port.tid(c->ingress.owner.cfg.port.context)==c->ingress.owner.cfg.worker_tid;}
int bg_fail(struct bg_control*c,uint32_t e){if(!c||!e)return BG_REJECT;uint32_t z=0;__atomic_compare_exchange_n(&c->error,&z,e,0,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE);if(ld(&c->ingress.prepared))lo_abort(&c->ingress.owner);return BG_FAILED;}
int bg_prepare(struct bg_control*c,const struct lo_config*q){if(!c||ld(&c->begun)||ld(&c->error))return BG_REJECT;if(lw_prepare(&c->ingress,q)!=LO_OK)return BG_REJECT;return lo_bootstrap_arm(&c->ingress.owner)==LO_OK?BG_OK:BG_REJECT;}
int bg_begin(struct bg_control*c){
 if(!worker(c)||ld(&c->error)||ld(&c->ingress.error))return BG_REJECT;
 uint32_t request=ld(&c->ingress.mailbox),e=request&7;
 /* A queued INACT still constructs the fixed paused bundle. No ACK is
  * allowed before all four ownership transfers and native drain proof.
  * Source START remains control4/no snapshot; audio/menu START stay paused. */
 if(e!=LO_INIT&&e!=LO_ACT&&e!=LO_INACT)return BG_PENDING;
 uint32_t z=0;if(!__atomic_compare_exchange_n(&c->begun,&z,1,0,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))return BG_REJECT;return BG_OK;
}
int bg_enter(struct bg_control*c,uint32_t bit){
 if(!worker(c)||!ld(&c->begun)||ld(&c->error)||ld(&c->ingress.error)||ld(&c->inflight))return BG_REJECT;
 uint32_t mask=ld(&c->accepted),want=mask==0?BG_SOURCE:mask==1?BG_OBSERVER:mask==3?BG_AUDIO:mask==7?BG_MENU:0;
 if(bit!=want||!bit)return BG_REJECT;
 /* The entire fixed bundle was accepted by begin. An early native INACT
  * revokes already published providers; an in-flight adoption is allowed
  * to publish its ownership once, then immediately observes that request. */
 st(&c->inflight,bit);return BG_OK;
}
int bg_adopt(struct bg_control*c,uint32_t bit){
 if(!worker(c)||!bit||ld(&c->inflight)!=bit||(ld(&c->accepted)&bit))return BG_REJECT;
 /* A native API must have affirmatively transferred its self reference.
  * This function records ownership even if Exit raced that API's return. */
 __atomic_fetch_or(&c->accepted,bit,__ATOMIC_RELEASE);st(&c->inflight,0);
 if(ld(&c->error)||ld(&c->ingress.error)){lo_abort(&c->ingress.owner);return BG_FAILED;}
 if((ld(&c->ingress.mailbox)&7)==LO_INACT)lo_close(&c->ingress.owner);
 return BG_OK;
}
int bg_event(struct bg_control*c,uint32_t e,uint32_t tid){if(!c)return LO_INVALID;return lw_event(&c->ingress,e,tid);}
int bg_tick(struct bg_control*c,uint32_t now){
 if(!worker(c))return LO_INVALID;
 if(ld(&c->error)||ld(&c->ingress.error)){lo_abort(&c->ingress.owner);return LO_ERROR;}
 /* No lifecycle ACK is possible during a partial/ambiguous bootstrap. */
 if(ld(&c->inflight)||ld(&c->accepted)!=BG_ALL)return LO_PENDING;
 int r=lw_tick(&c->ingress,now);if(r==LO_ERROR||r==LO_INVALID){bg_fail(c,100);return r;}
 if(ld(&c->ingress.owner.bootstrap_state)==3)st(&c->ready,1);
 /* An initial native INACT supersedes the initial-grant route. The normal
  * coordinator proves both drains, ACKs INACT once, and only the original
  * ACT callback authorizes resume. Publish readiness after a fresh ACT sample
  * and its completion, never by fabricating initial-grant/barrier fields. */
 struct lo_control*o=&c->ingress.owner;struct lo_status*s=&o->status;
 uint32_t request=ld(&o->request),generation=request>>3;
 if(ld(&o->bootstrap_state)==4&&(request&7u)==LO_ACT&&generation&&
    s->worker_generation==generation&&o->worker_event==LO_ACT&&
    ld(&o->proof_generation)==generation&&ld(&o->inact_claim)==generation&&
    ld(&o->act_claim)==generation&&s->barrier_verified_epoch&&
    s->barrier_verified_epoch==s->audio.epoch&&
    s->audio.epoch==ld(&o->audio_epoch)&&s->menu.control.epoch==ld(&o->menu_epoch)&&
    (s->audio.phase==LP_WAKING||s->audio.phase==LP_ACTIVE)&&
    (s->menu.control.phase==LP_WAKING||s->menu.control.phase==LP_ACTIVE)&&
    !ld(&o->error)&&!ld(&c->ingress.error)&&ld(&o->request)==request)st(&c->ready,1);
 return r;
}
