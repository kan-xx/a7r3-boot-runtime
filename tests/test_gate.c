/* Cold battery-pull pre-start LO_INACT -> LO_ACT bootstrap gate host test. */
#include "../startup-owner/bootstrap/bootstrap_gate.h"
static struct bg_control bundle;
#include <stdio.h>
#include <assert.h>
#include <string.h>
static unsigned checks,who=77,native_phase,pending,sends,barriers,send_error,barrier_error,menu_returned,menu_live,menu_resume_reject,menu_schedule_busy,queries_busy,native_bad,menu_identity_bad,fault_inside_resume,inact_inside_retry;
static unsigned audio_empty;
static struct lp_control a,m;
#define C(x) do{assert(x);checks++;}while(0)
static uint32_t tid(void*p){(void)p;return who;}
static int ap(const uint8_t*n,uint32_t e){C(n[0]==1);return lp_pause(&a,e);}
static int ar(const uint8_t*n,uint32_t e){C(n[0]==1&&(who==66||bundle.ingress.owner.bootstrap_state==2));if(fault_inside_resume){fault_inside_resume=0;who=77;native_bad=1;C(lo_tick(&bundle.ingress.owner,50)==LO_ERROR);who=66;}return lp_resume(&a,e);}
static int mp(const uint8_t*n,uint32_t e){C(n[0]==2);return lp_pause(&m,e);}
static int mr(const uint8_t*n,uint32_t e){C(n[0]==2);C(who==66||bundle.ingress.owner.bootstrap_state==2||lp_phase(&m)==LP_WAKING||e<lp_epoch(&m));if(who==77&&inact_inside_retry){inact_inside_retry=0;who=66;C(lo_event(&bundle.ingress.owner,LO_INACT)==LO_PENDING);who=77;native_phase=3;pending=1;}if(menu_resume_reject)return LP_BUSY;int r=lp_resume(&m,e);if(menu_schedule_busy){menu_schedule_busy=0;return LP_BUSY;}return r;}
static int aq(struct lp_status*p){C(who==77);if(queries_busy)return LP_BUSY;memset(p,0,sizeof*p);p->abi=1;p->bytes=sizeof*p;p->build=LO_AUDIO_BUILD;lp_report(&a,p);p->worker_epoch=p->wake_epoch=p->epoch;p->local_drained=p->native_quiet=p->phase==LP_PARKED;p->retained_resources=1;p->reserved=audio_empty;return LP_OK;}
static int mq(struct mp_power_report*p){C(who==77);memset(p,0,sizeof*p);p->abi=1;p->bytes=sizeof*p;p->build=LO_MENU_BUILD;p->pid=menu_identity_bad?999:158;p->owner=392;p->ui_epoch=p->wake_epoch=lp_epoch(&m);p->callback_returned=menu_returned;p->route_suspended=lp_phase(&m)==LP_PARKED;p->view_live=menu_live;p->reference_retained=1;p->control.abi=1;p->control.bytes=96;p->control.build=LO_MENU_BUILD;lp_report(&m,&p->control);p->control.local_drained=p->control.phase==LP_PARKED;return LP_OK;}
static int ns(void*x,uint32_t cmd,struct lo_im_state*p){(void)x;C(cmd==0x940122||cmd==0x940123);*p=(struct lo_im_state){158,0x123400,0xfffe,0x20000003,native_phase,pending};if(native_bad)p->descriptor++;return 0;}
static int sendc(void*x,uint32_t cmd,uint32_t mid){(void)x;C(who==77&&mid==0xfffe);C(cmd==0x940122||cmd==0x940123);sends++;return send_error;}
static int barrier(void*x,struct bp_report*p){(void)x;C(who==77&&lp_phase(&a)==LP_PARKED);barriers++;memset(p,0,sizeof*p);p->abi=1;p->bytes=sizeof*p;p->stage=8;p->barrier_ok=p->notify_unchanged=1;return barrier_error;}
static struct ap_power_api aa={1,sizeof aa,LO_AUDIO_BUILD,ap,ar,aq};static struct mp_power_api ma={1,sizeof ma,LO_MENU_BUILD,mp,mr,mq};
static int event(unsigned e){who=66;int r=lo_event(&bundle.ingress.owner,e);who=77;return r;}
static void setup(void){memset(&bundle.ingress.owner,0,sizeof bundle.ingress.owner);memset(&a,0,sizeof a);memset(&m,0,sizeof m);native_phase=2;pending=sends=barriers=send_error=barrier_error=menu_live=menu_resume_reject=menu_schedule_busy=queries_busy=native_bad=menu_identity_bad=fault_inside_resume=inact_inside_retry=0;menu_returned=1;who=77;struct lo_config c={{0,tid,ns,sendc,barrier},&aa,&ma,158,66,77,0x123400,{1},{2}};C(lo_init(&bundle.ingress.owner,&c)==LO_OK);C(event(LO_INIT)==LO_OK);C(lo_tick(&bundle.ingress.owner,0)==LO_OK);}
static void park(void){C(lp_park(&a,lp_epoch(&a))==LP_OK);C(lp_park(&m,lp_epoch(&m))==LP_OK);}
static void initial(void){setup();memset(&bundle,0,sizeof bundle);memset(&a,0,sizeof a);memset(&m,0,sizeof m);C(bg_event(&bundle,LO_INIT,100)==LO_OK);struct lo_config q={{0,tid,ns,sendc,barrier},&aa,&ma,158,66,77,0x123400,{1},{2}};C(bg_prepare(&bundle,&q)==BG_OK);}
static void adopt(unsigned bit){C(bg_enter(&bundle,bit)==BG_OK);C(bg_enter(&bundle,bit)==BG_REJECT);C(bg_tick(&bundle,0)==LO_PENDING&&!sends);if(bit==BG_AUDIO){memset(&a,0,sizeof a);C(lp_pause(&a,1)==LP_OK);}if(bit==BG_MENU){memset(&m,0,sizeof m);C(lp_pause(&m,1)==LP_OK);}C(bg_adopt(&bundle,bit)==BG_OK);C(bg_adopt(&bundle,bit)==BG_REJECT);}
int main(void){
 initial();C(bg_enter(&bundle,BG_SOURCE)==BG_REJECT);C(bg_begin(&bundle)==BG_OK);C(bg_enter(&bundle,BG_AUDIO)==BG_REJECT);adopt(BG_SOURCE);adopt(BG_OBSERVER);adopt(BG_AUDIO);adopt(BG_MENU);park();C(bg_tick(&bundle,0)==LO_PENDING&&!bundle.ready&&!sends);C(bg_tick(&bundle,1)==LO_PENDING&&!bundle.ready);C(bg_tick(&bundle,2)==LO_OK&&bundle.ready);C(!sends&&a.resumes==1&&m.resumes==1);
 for(unsigned at=0;at<4;at++){
  initial();C(bg_begin(&bundle)==BG_OK);unsigned bits[4]={BG_SOURCE,BG_OBSERVER,BG_AUDIO,BG_MENU};
  for(unsigned i=0;i<4;i++){adopt(bits[i]);if(i==at){who=66;C(bg_event(&bundle,LO_INACT,who)==LO_PENDING);who=77;native_phase=3;pending=1;}if(i<3)C(bg_tick(&bundle,0)==LO_PENDING&&!sends);}
  if(lp_phase(&a)==LP_CLOSING)C(lp_park(&a,lp_epoch(&a))==LP_OK);if(lp_phase(&m)==LP_CLOSING)C(lp_park(&m,lp_epoch(&m))==LP_OK);
  C(bg_tick(&bundle,0)==LO_PENDING&&!sends);C(bg_tick(&bundle,1)==LO_OK&&sends==1&&!bundle.ready);C(!a.resumes&&!m.resumes&&lp_closed(&a)&&lp_closed(&m));
 }
 for(unsigned early=0;early<2;early++){
  initial();
  if(early==0){memset(&bundle,0,sizeof bundle);C(bg_event(&bundle,LO_INIT,100)==LO_OK);}
  who=66;C(bg_event(&bundle,LO_INACT,who)==LO_PENDING);who=77;
  if(early==0){struct lo_config q={{0,tid,ns,sendc,barrier},&aa,&ma,158,66,77,0x123400,{1},{2}};C(bg_prepare(&bundle,&q)==BG_OK);}
  C(bg_begin(&bundle)==BG_OK&&bundle.begun&&!bundle.ready&&!sends);
  adopt(BG_SOURCE);adopt(BG_OBSERVER);adopt(BG_AUDIO);adopt(BG_MENU);
  if(lp_phase(&a)==LP_CLOSING)C(lp_park(&a,lp_epoch(&a))==LP_OK);
  if(lp_phase(&m)==LP_CLOSING)C(lp_park(&m,lp_epoch(&m))==LP_OK);
  native_phase=3;pending=0;C(bg_tick(&bundle,0)==LO_PENDING&&!sends&&!bundle.ready);
  C(bg_tick(&bundle,1)==LO_PENDING&&!sends&&!bundle.ready);
  pending=1;C(bg_tick(&bundle,2)==LO_OK&&sends==1&&!bundle.ready);
  C(!a.resumes&&!m.resumes);C(bg_tick(&bundle,3)==LO_ALREADY&&sends==1&&!bundle.ready);
  native_phase=4;pending=0;who=66;C(bg_event(&bundle,LO_SUS,who)==LO_OK);C(bg_event(&bundle,LO_RES,who)==LO_OK);
  native_phase=5;pending=1;C(bg_event(&bundle,LO_ACT,who)==LO_PENDING);who=77;
  C(bg_tick(&bundle,4)==LO_OK&&sends==2&&!bundle.ready);
  C(bg_tick(&bundle,5)==LO_PENDING&&bundle.ready&&sends==2);
  C(bundle.ingress.owner.bootstrap_state==4&&bundle.ingress.owner.status.bootstrap_barrier==0);
  C(bundle.ingress.owner.proof_generation==1&&bundle.ingress.owner.inact_claim==1&&bundle.ingress.owner.act_claim==1);
  C(a.resumes==1&&m.resumes==1);
  for(unsigned i=0;i<20;i++){C(bg_tick(&bundle,6+i)==LO_PENDING&&sends==2&&bundle.ready);}
 }
 initial();C(bg_begin(&bundle)==BG_OK);C(bg_enter(&bundle,BG_SOURCE)==BG_OK);C(bg_event(&bundle,LO_EXIT,88)==LO_ERROR);C(bg_adopt(&bundle,BG_SOURCE)==BG_FAILED&&bundle.accepted==BG_SOURCE);C(bg_tick(&bundle,0)==LO_ERROR&&!sends);C(bg_enter(&bundle,BG_OBSERVER)==BG_REJECT);
 printf("FULL_BOOTSTRAP_GATE checks=%u cases=8 failures=0\n",checks);return 0;
}
