#include "owner.h"
static uint32_t ld(const uint32_t*p){return __atomic_load_n(p,__ATOMIC_ACQUIRE);}
static void st(uint32_t*p,uint32_t v){__atomic_store_n(p,v,__ATOMIC_RELEASE);}
static void clear(void*p,unsigned n){uint8_t*b=p;while(n--)*b++=0;}
static void copy(void*d,const void*s,unsigned n){uint8_t*a=d;const uint8_t*b=s;while(n--)*a++=*b++;}
static int live(const struct lo_control*c){return c&&ld(&c->initialized);}
static int own(const struct lo_control*c,uint32_t id){return live(c)&&c->cfg.port.tid(c->cfg.port.context)==id;}
static int fail(struct lo_control*c,uint32_t why){
 uint32_t zero=0;if(__atomic_compare_exchange_n(&c->error,&zero,why,0,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE)){
  /* A failure discovered after ACT must also close a provider that already
   * reopened. Calls are nonblocking; LP_BUSY still revokes actual admission. */
  uint32_t a=ld(&c->audio_epoch),m=ld(&c->menu_epoch);
  if(a<UINT32_MAX)st(&c->audio_pause_result,c->cfg.audio->pause(c->cfg.audio_id,a+1));
  if(m<UINT32_MAX)st(&c->menu_pause_result,c->cfg.menu->pause(c->cfg.menu_id,m+1));
 }
 return LO_ERROR;
}
static void max_epoch(uint32_t*p,uint32_t value){uint32_t old=ld(p);while(value>old&&!__atomic_compare_exchange_n(p,&old,value,0,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE));}
static int same(const struct lo_control*c,uint32_t g,uint32_t e){return ld(&c->request)==((g<<3)|e);}
static void revoke(struct lo_control*c){
 uint32_t a=ld(&c->audio_epoch),m=ld(&c->menu_epoch);
 if(a==UINT32_MAX||m==UINT32_MAX){fail(c,1);return;}
 st(&c->audio_pause_result,c->cfg.audio->pause(c->cfg.audio_id,a+1));
 st(&c->menu_pause_result,c->cfg.menu->pause(c->cfg.menu_id,m+1));
}
uint32_t lo_size(void){return sizeof(struct lo_control);}
int lo_init(struct lo_control*c,const struct lo_config*q){
 if(!c||ld(&c->initialized)||!q||!q->port.tid||!q->port.native_state||!q->port.completion||!q->port.barrier||!q->pid||!q->im_tid||!q->worker_tid||q->im_tid==q->worker_tid||!q->descriptor)return LO_INVALID;
 if(q->port.tid(q->port.context)!=q->worker_tid||!q->audio||!q->menu||q->audio->abi!=1||q->audio->bytes!=sizeof*q->audio||q->audio->build!=LO_AUDIO_BUILD||q->menu->abi!=1||q->menu->bytes!=sizeof*q->menu||q->menu->build!=LO_MENU_BUILD||!q->audio->pause||!q->audio->resume||!q->audio->query||!q->menu->pause||!q->menu->resume||!q->menu->query)return LO_INVALID;
 unsigned a=0,m=0;for(unsigned i=0;i<16;i++){a|=q->audio_id[i];m|=q->menu_id[i];}if(!a||!m)return LO_INVALID;
 clear(c,sizeof*c);copy(&c->cfg,q,sizeof*q);c->status.abi=1;c->status.bytes=sizeof c->status;c->status.build=LO_BUILD;st(&c->initialized,1);return LO_OK;
}
int lo_bootstrap_arm(struct lo_control*c){
 if(!c||!own(c,c->cfg.worker_tid)||ld(&c->handoff_sealed)||ld(&c->request)||ld(&c->error)||ld(&c->bootstrap_state))return LO_INVALID;
 st(&c->audio_epoch,1);st(&c->menu_epoch,1);st(&c->bootstrap_state,1);return LO_OK;
}
int lo_adopt(struct lo_control*c,uint32_t request){
 if(!c||!own(c,c->cfg.worker_tid)||ld(&c->handoff_sealed)||ld(&c->error))return LO_INVALID;
 uint32_t e=request&7u,g=request>>3,old=ld(&c->request),oe=old&7u,og=old>>3;
 if(!((e==LO_INIT&&!g)||(e==LO_ACT&&g==1)||(e==LO_INACT&&g)))return LO_INVALID;
 if(g<og||(oe==LO_INACT&&e!=LO_INACT)||(oe==LO_ACT&&e==LO_INIT))return LO_INVALID;
 st(&c->request,request);if(e==LO_INACT)revoke(c);return ld(&c->error)?LO_ERROR:LO_OK;
}
int lo_close(struct lo_control*c){if(!live(c))return LO_INVALID;revoke(c);return ld(&c->error)?LO_ERROR:LO_OK;}
int lo_abort(struct lo_control*c){if(!live(c))return LO_INVALID;fail(c,61);revoke(c);return LO_ERROR;}
int lo_event(struct lo_control*c,uint32_t e){
 if(!c||!own(c,c->cfg.im_tid)||e<LO_INIT||e>LO_EXIT)return LO_INVALID;
 st(&c->handoff_sealed,1);
 if(ld(&c->error)){if(e==LO_INACT||e==LO_EXIT)revoke(c);return LO_ERROR;}
 uint32_t request=ld(&c->request),old=request&7u,g=request>>3;
 if(e==LO_INIT){if(old)return LO_ALREADY;st(&c->request,(g<<3)|e);return LO_OK;}
 if(!old)return LO_INVALID;
 if(e==LO_ACT&&old==LO_ACT)return LO_ALREADY;
 if(e==LO_ACT&&old==LO_INIT&&!g){st(&c->request,(1u<<3)|e);return LO_PENDING;}
 if(e==LO_INACT||e==LO_EXIT){
  if(g==(UINT32_MAX>>3)){revoke(c);return fail(c,2);}
  /* An overlapping native wave cannot safely reuse a queue message which
   * carries no epoch. Do not emit a second completion for that ambiguity. */
  if(e==LO_INACT&&((old==LO_INACT&&ld(&c->inact_claim)==g)||(old==LO_ACT&&ld(&c->act_claim)!=g))){revoke(c);return fail(c,3);}
  st(&c->request,((g+1)<<3)|e);revoke(c);return ld(&c->error)?LO_ERROR:LO_PENDING;
 }
 if(!g||ld(&c->proof_generation)!=g||ld(&c->inact_claim)!=g)return fail(c,4);
 if(e==LO_SUS){if(old!=LO_INACT)return fail(c,5);st(&c->request,(g<<3)|e);return LO_OK;}
 if(e==LO_RES){if(old!=LO_SUS)return fail(c,6);st(&c->request,(g<<3)|e);return LO_OK;}
 if(e==LO_ACT){
  if(old!=LO_RES&&old!=LO_INACT)return fail(c,7);
  /* Only this serialized IM callback can change PARKED to WAKING. The
   * worker never starts a resume from PARKED, including after BUSY. */
  st(&c->request,(g<<3)|e);
  if(!ld(&c->error))st(&c->audio_resume_result,c->cfg.audio->resume(c->cfg.audio_id,ld(&c->audio_epoch)));
  if(!ld(&c->error))st(&c->menu_resume_result,c->cfg.menu->resume(c->cfg.menu_id,ld(&c->menu_epoch)));
  /* A worker fault can race an already-entered callback. Retain references
   * and close again before this callback returns; an error flag alone never
   * proves callback retirement or permits freeing any provider. */
  if(ld(&c->error)){revoke(c);return LO_ERROR;}
  return LO_PENDING;
 }
 return LO_INVALID;
}
static int audio_sample(struct lo_control*c){
 struct lp_status*p=&c->status.audio;int rc=c->cfg.audio->query(p);if(rc==LP_BUSY)return LO_PENDING;
 if(rc||p->abi!=1||p->bytes!=sizeof*p||p->build!=LO_AUDIO_BUILD||p->reserved>2||p->error||p->phase==LP_FAULT)return fail(c,10);
 if(p->epoch<ld(&c->audio_epoch))return fail(c,11);max_epoch(&c->audio_epoch,p->epoch);return LO_OK;
}
static int menu_sample(struct lo_control*c){
 struct mp_power_report*p=&c->status.menu;int rc=c->cfg.menu->query(p);if(rc==LP_BUSY)return LO_PENDING;
 if(rc||p->abi!=1||p->bytes!=sizeof*p||p->build!=LO_MENU_BUILD||p->pid!=c->cfg.pid||p->error||p->control.abi!=1||p->control.bytes!=sizeof p->control||p->control.build!=LO_MENU_BUILD||p->control.error||p->control.phase==LP_FAULT)return fail(c,12);
 if(p->control.epoch<ld(&c->menu_epoch))return fail(c,13);max_epoch(&c->menu_epoch,p->control.epoch);return LO_OK;
}
static int audio_parked(const struct lp_status*p){return p->phase==LP_PARKED&&p->epoch&&p->worker_epoch==p->epoch&&p->local_drained&&p->native_quiet&&(p->word&3)==1&&!p->pending_audio&&!p->pending_source&&!p->pending_registration&&!p->pending_loop&&p->retained_resources;}
static int menu_parked(const struct mp_power_report*p){return p->control.phase==LP_PARKED&&p->control.epoch&&p->ui_epoch==p->control.epoch&&p->control.local_drained&&(p->control.word&3)==1&&p->callback_returned&&p->route_suspended&&!p->view_live&&!p->transaction_pending&&p->reference_retained;}
static int send_once(struct lo_control*c,uint32_t g,uint32_t e){
 uint32_t*claim=e==LO_INACT?&c->inact_claim:&c->act_claim,cmd=e==LO_INACT?0x940122u:0x940123u;
 if(ld(claim)==g)return LO_ALREADY;
 struct lo_im_state im={0};int rc=c->cfg.port.native_state(c->cfg.port.context,cmd,&im);if(rc==1)return LO_PENDING;
 if(rc||im.pid!=c->cfg.pid||im.descriptor!=c->cfg.descriptor||im.module_id!=0xfffe||im.type!=0x20000003)return fail(c,20);
 if(im.state!=(e==LO_INACT?3u:5u)||!im.pending)return LO_PENDING;
 if(ld(&c->error))return LO_ERROR;if(!same(c,g,e))return LO_PENDING;
 /* Latch before the original queue hand-off. Error/unknown outcome never
  * retries; successful enqueue is not confused with consumer processing. */
 st(claim,g);if(e==LO_INACT)c->status.inact_sends++;else c->status.act_sends++;
 if(c->cfg.port.completion(c->cfg.port.context,cmd,0xfffe))return fail(c,21);
 return LO_OK;
}
static int initial_request(const struct lo_control*c){uint32_t r=ld(&c->request);return !ld(&c->error)&&(r==LO_INIT||r==((1u<<3)|LO_ACT));}
static int grant_initial(struct lo_control*c,int audio){
 if(!initial_request(c))return LO_PENDING;
 uint32_t result=audio?c->cfg.audio->resume(c->cfg.audio_id,1):c->cfg.menu->resume(c->cfg.menu_id,1);
 if(audio)c->status.bootstrap_audio_result=result;else c->status.bootstrap_menu_result=result;
 /* A newer INACT may cross the call. New provider pause semantics advance
  * even PARKED epochs, so an old grant cannot follow a successful revoke.
  * A contended revoke changes the grant word; close again after the call. */
 if(!initial_request(c)){revoke(c);return ld(&c->error)?LO_ERROR:LO_PENDING;}
 if(result!=LP_OK&&result!=LP_ALREADY&&result!=LP_BUSY)return fail(c,42);
 return LO_OK;
}
static int bootstrap_tick(struct lo_control*c,uint32_t now){
 uint32_t b=ld(&c->bootstrap_state);if(!b||b==4)return LO_OK;
 if(!initial_request(c)){st(&c->bootstrap_state,4);return LO_OK;}
 struct lo_status*s=&c->status;
 if(b!=3&&(uint32_t)(now-s->started_ms)>=10000)return fail(c,40);
 int r=audio_sample(c);if(r)return r;r=menu_sample(c);if(r)return r;
 if(!initial_request(c))return LO_PENDING;
 struct lp_status*a=&s->audio;struct mp_power_report*m=&s->menu;
 if(a->epoch!=1||m->control.epoch!=1)return fail(c,41);
 if(b==1){
  if(!audio_parked(a)||!menu_parked(m))return LO_PENDING;
  if(!s->bootstrap_barrier){
   s->bootstrap_barrier=1;
   if(c->cfg.port.barrier(c->cfg.port.context,&s->barrier)||s->barrier.abi!=1||s->barrier.bytes!=sizeof s->barrier||s->barrier.stage!=8||s->barrier.error||!s->barrier.barrier_ok||!s->barrier.notify_unchanged||s->barrier.retained_ids||s->barrier.held_message)return fail(c,43);
   return LO_PENDING; /* Both local return boundaries sampled next turn. */
  }
  s->bootstrap_barrier=2;st(&c->bootstrap_state,2);b=2;
 }
 if(b==2){
  if(a->phase==LP_PARKED){r=grant_initial(c,1);if(r)return r;}
  if(m->control.phase==LP_PARKED||m->control.phase==LP_WAKING){r=grant_initial(c,0);if(r)return r;}
  /* Query again on the next turn. Never report a queued request as an
   * observed WAKING/ACTIVE state or as a physical playback success. */
  if((a->phase!=LP_WAKING&&a->phase!=LP_ACTIVE)||(m->control.phase!=LP_WAKING&&m->control.phase!=LP_ACTIVE))return LO_PENDING;
  st(&c->bootstrap_state,3);
 }else if(m->control.phase==LP_WAKING){r=grant_initial(c,0);if(r)return r;}
 return LO_OK;
}
int lo_tick(struct lo_control*c,uint32_t now){
 if(!c||!own(c,c->cfg.worker_tid))return LO_INVALID;st(&c->handoff_sealed,1);if(ld(&c->error))return LO_ERROR;
 uint32_t request=ld(&c->request),e=request&7u,g=request>>3;struct lo_status*s=&c->status;
 if(!e)return LO_INVALID;
 if(s->worker_generation!=g||c->worker_event!=e){s->worker_generation=g;c->worker_event=e;s->started_ms=now;}
 int bootstrap_result=bootstrap_tick(c,now);if(bootstrap_result!=LO_OK)return bootstrap_result;
 if(e==LO_INIT||e==LO_SUS||e==LO_RES)return LO_OK;
 if(e==LO_ACT){
  /* ACT acknowledges that this module processed the event. It never waits
   * for a card and it does not declare audio/UI ready. */
  int sent=send_once(c,g,e);if(sent!=LO_ALREADY)return sent;
  /* Resume may be accepted while the UI timer mutex was busy. A retry is
   * permitted ONLY after observing WAKING at the same epoch. That phase
   * cannot become PARKED again without a newer epoch, so this retry cannot
   * authorize a new resume after a subsequent INACT. */
  int r=audio_sample(c);if(r)return r;r=menu_sample(c);if(r)return r;if(!same(c,g,e))return LO_PENDING;
  if(s->menu.control.phase==LP_WAKING)c->cfg.menu->resume(c->cfg.menu_id,s->menu.control.epoch);
  return s->audio.phase==LP_ACTIVE&&s->menu.control.phase==LP_ACTIVE?LO_OK:LO_PENDING;
 }
 if(e!=LO_INACT&&e!=LO_EXIT)return LO_INVALID;
 if(e==LO_INACT&&ld(&c->inact_claim)==g)return LO_ALREADY;
 if(e==LO_EXIT&&s->exit_drained)return LO_OK;
 if((uint32_t)(now-s->started_ms)>=10000)return fail(c,30);
 int rc=audio_sample(c);if(rc)return rc;rc=menu_sample(c);if(rc)return rc;if(!same(c,g,e))return LO_PENDING;
 struct lp_status*a=&s->audio;struct mp_power_report*m=&s->menu;
 if(a->phase==LP_ACTIVE||a->phase==LP_WAKING){if(a->epoch==UINT32_MAX)return fail(c,31);st(&c->audio_pause_result,c->cfg.audio->pause(c->cfg.audio_id,a->epoch+1));return LO_PENDING;}
 if(m->control.phase==LP_ACTIVE||m->control.phase==LP_WAKING){if(m->control.epoch==UINT32_MAX)return fail(c,31);st(&c->menu_pause_result,c->cfg.menu->pause(c->cfg.menu_id,m->control.epoch+1));return LO_PENDING;}
 if(!audio_parked(a)||!menu_parked(m))return LO_PENDING;
 if(s->barrier_verified_epoch!=a->epoch){
  if(c->barrier_pending_epoch==a->epoch){s->barrier_verified_epoch=a->epoch;c->barrier_pending_epoch=0;}
  else{
   if(s->barrier_attempt_epoch==a->epoch)return fail(c,32);s->barrier_attempt_epoch=a->epoch;
   if(c->cfg.port.barrier(c->cfg.port.context,&s->barrier)||s->barrier.abi!=1||s->barrier.bytes!=sizeof s->barrier||s->barrier.stage!=8||s->barrier.error||!s->barrier.barrier_ok||!s->barrier.notify_unchanged||s->barrier.retained_ids||s->barrier.held_message)return fail(c,33);
   c->barrier_pending_epoch=a->epoch;return LO_PENDING; /* Fresh clock and both queries next tick. */
  }
 }
 if(!same(c,g,e))return LO_PENDING;st(&c->proof_generation,g);
 if(e==LO_EXIT){s->exit_drained=1;return LO_OK;}
 return send_once(c,g,e);
}
int lo_report(const struct lo_control*c,struct lo_status*out){
 if(!c||!out||!own(c,c->cfg.worker_tid))return LO_INVALID;copy(out,&c->status,sizeof*out);
 uint32_t request=ld(&c->request);out->bootstrap_state=ld(&c->bootstrap_state);out->event=request&7u;out->generation=request>>3;out->error=ld(&c->error);out->audio_epoch=ld(&c->audio_epoch);out->menu_epoch=ld(&c->menu_epoch);out->proof_generation=ld(&c->proof_generation);out->inact_claim=ld(&c->inact_claim);out->act_claim=ld(&c->act_claim);out->audio_pause_result=ld(&c->audio_pause_result);out->menu_pause_result=ld(&c->menu_pause_result);out->audio_resume_result=ld(&c->audio_resume_result);out->menu_resume_result=ld(&c->menu_resume_result);return LO_OK;
}
