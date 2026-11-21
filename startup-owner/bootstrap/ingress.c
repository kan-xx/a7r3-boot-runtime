#include "ingress.h"
static uint32_t ld(const uint32_t*p){return __atomic_load_n(p,__ATOMIC_ACQUIRE);}
static void st(uint32_t*p,uint32_t x){__atomic_store_n(p,x,__ATOMIC_RELEASE);}
static int cas(uint32_t*p,uint32_t*old,uint32_t x){return __atomic_compare_exchange_n(p,old,x,0,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE);}
static int error(struct lw_control*c,uint32_t why){uint32_t zero=0;cas(&c->error,&zero,why);if(ld(&c->prepared))lo_abort(&c->owner);return LO_ERROR;}
uint32_t lw_size(void){return sizeof(struct lw_control);}
int lw_event(struct lw_control*c,uint32_t e,uint32_t tid){
 if(!c||!tid||e<LO_INIT||e>LO_EXIT)return LO_INVALID;
 if(e==LO_EXIT){st(&c->exit_tid,tid);return error(c,71);}
 if(ld(&c->error))return LO_ERROR;
 if(e==LO_INIT){
  uint32_t zero=0;if(!cas(&c->init_tid,&zero,tid))return LO_ALREADY;
  zero=0;if(!cas(&c->mailbox,&zero,LO_INIT))return error(c,72);
  return LO_OK;
 }
 uint32_t mt=0;cas(&c->main_tid,&mt,tid);if(ld(&c->main_tid)!=tid)return error(c,73);
 if(ld(&c->prepared)&&c->owner.cfg.im_tid!=tid)return error(c,74);
 for(unsigned attempt=0;attempt<4;attempt++){
  if(ld(&c->error))return LO_ERROR;
  uint32_t request=ld(&c->mailbox);
  if(request&LW_READY)return lo_event(&c->owner,e);
  uint32_t old=request&7u,g=request>>3,next;
  if(e==LO_ACT&&old==LO_ACT)return LO_ALREADY;
  if(e==LO_ACT&&old==LO_INIT&&!g)next=(1u<<3)|e;
  else if(e==LO_INACT&&(old==LO_INIT||old==LO_INACT)&&g<0x0fffffffu)next=((g+1)<<3)|e;
  else return error(c,75);
  if(!cas(&c->mailbox,&request,next))continue;
  if(e==LO_INACT&&ld(&c->prepared))lo_close(&c->owner);
  if(ld(&c->error)){if(ld(&c->prepared))lo_abort(&c->owner);return LO_ERROR;}
  return LO_PENDING;
 }
 return error(c,76);
}
int lw_prepare(struct lw_control*c,const struct lo_config*q){
 if(!c||!q||!q->port.tid||q->port.tid(q->port.context)!=q->worker_tid)return LO_INVALID;
 if(ld(&c->error))return LO_ERROR;
 if(!ld(&c->init_tid)||!ld(&c->mailbox))return LO_PENDING;
 uint32_t mt=ld(&c->main_tid);if(mt&&mt!=q->im_tid)return error(c,77);
 uint32_t zero=0;if(!cas(&c->prepare_claim,&zero,1))return LO_ALREADY;
 int r=lo_init(&c->owner,q);if(r!=LO_OK)return error(c,78);
 st(&c->prepared,1);
 /* A callback may have raced configuration publication. Recheck its identity
  * and terminal Exit, and revoke a queued early INACT before returning. */
 mt=ld(&c->main_tid);if((mt&&mt!=q->im_tid)||ld(&c->error))return error(c,79);
 if((ld(&c->mailbox)&7u)==LO_INACT)lo_close(&c->owner);
 return LO_OK;
}
int lw_tick(struct lw_control*c,uint32_t now){
 if(!c||!ld(&c->prepared)||c->owner.cfg.port.tid(c->owner.cfg.port.context)!=c->owner.cfg.worker_tid)return LO_INVALID;
 if(ld(&c->error)){lo_abort(&c->owner);return LO_ERROR;}
 uint32_t request=ld(&c->mailbox);
 if(!(request&LW_READY)){
  if(lo_adopt(&c->owner,request)!=LO_OK)return error(c,80);
  if(ld(&c->error)){lo_abort(&c->owner);return LO_ERROR;}
  /* A callback changes the same packed word. Losing CAS means re-adopt on
   * the next tick; no ACK/resume and no unbounded spinning in this turn. */
  if(!cas(&c->mailbox,&request,request|LW_READY))return LO_PENDING;
 }
 if(ld(&c->error)){lo_abort(&c->owner);return LO_ERROR;}
 return lo_tick(&c->owner,now);
}
int lw_report(const struct lw_control*c,struct lw_status*out){
 if(!c||!out||!ld(&c->prepared)||c->owner.cfg.port.tid(c->owner.cfg.port.context)!=c->owner.cfg.worker_tid)return LO_INVALID;
 struct lw_status s={1,sizeof s,LW_BUILD,ld(&c->mailbox),ld(&c->error),ld(&c->prepared),ld(&c->init_tid),ld(&c->main_tid),ld(&c->exit_tid),ld(&c->owner.error)};*out=s;return LO_OK;
}
