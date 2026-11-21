#include "optional_loader.h"
void tl_init(struct tl_report*r){if(r)*r=(struct tl_report){.abi=1,.bytes=sizeof*r};}
static int full_act(uint32_t r){return(r&7u)==5u&&(r>>3)!=0;}
static int qualified(uint32_t ui,uint32_t r){return ui>=2&&(r==1||full_act(r));}
static int same_admission(const struct tl_port*p,uint32_t ui,uint32_t request){
 uint32_t u=0,v=0,r=0;
 return p->eligible(p->context,&u)&&u==ui&&p->activation(p->context,&v,&r)&&v==ui&&r==request;
}
int tl_step(struct tl_report*r,const struct tl_port*p){
 if(!r||!p||r->abi!=1||r->bytes!=sizeof*r||!p->eligible||!p->verify_protected_artifact||
    !p->load_verified||!p->resolve_verified_entry||!p->close_owned||
    !p->cancel_verification||!p->activation||!p->resolve_revoked)return -1;
 if(r->close_uncertain||r->replay_forbidden)return 0;
 int pure=r->stage==TL_IDLE||r->stage==TL_SAFE_BUSY||r->stage==TL_PREPARING||r->stage==TL_VERIFYING;
 int known=r->known_core&&(r->stage==TL_ACTIVATION_PENDING||r->stage==TL_ACTIVATION_EXHAUSTED||
             r->stage==TL_REVOKED||(r->stage==TL_ENTRY_RETURNED&&r->entry_result==0));
 /* REVOKED is reached only before this attempt's entry, with no handle or a
  * known successful caller close. It can resume on a strictly newer ACT even
  * before the first0, without resetting any pure verification/preparing state. */
 int revoked=r->stage==TL_REVOKED&&r->activation!=0;
 if(!pure&&!known&&!revoked)return 0;
 uint32_t ui=0,request=0;
 if(!p->activation(p->context,&ui,&request)||!qualified(ui,request))return 0;
 int new_act=0;
 if(known||revoked){
  if(request==r->activation){
   if(r->stage!=TL_ACTIVATION_PENDING||r->queue_results>=TL_MAX_ACTIVATION_RESULTS)return 0;
  }else{
   /* Original LO generation is monotonic and faults instead of wrapping. */
   if(!full_act(request)||(request>>3)<=(r->activation>>3))return 0;
   new_act=1;
  }
 }
 if(!r->known_core&&r->safe_busy_results>=TL_MAX_SAFE_BUSY_RESULTS){r->stage=TL_BUSY_EXHAUSTED;return 0;}
 if(!r->known_core&&r->preparing_results>=TL_MAX_PREPARING_RESULTS){r->stage=TL_PREPARING_EXHAUSTED;return 0;}
 uint32_t again=0;if(!p->eligible(p->context,&again)||again!=ui)return 0;
 if(new_act){r->activation_reentries++;r->queue_activation=request;r->queue_results=0;}
 r->activation=request;r->ui_tid=ui;r->attempted=1;r->attempts++;
 r->verify_calls++;int verification=p->verify_protected_artifact(p->context);
 if(verification==TL_VERIFY_MORE){
  if(r->known_core){
   r->verify_cancel_calls++;r->verify_cancel_result=(uint32_t)p->cancel_verification(p->context);
   r->stage=r->verify_cancel_result==1?TL_VERIFY_FAILED:TL_VERIFY_CANCEL_UNKNOWN;r->replay_forbidden=1;return 1;
  }
  r->verify_more_results++;
  if(r->verify_more_results>=TL_MAX_VERIFY_STEPS){
   r->verify_cancel_calls++;r->verify_cancel_result=(uint32_t)p->cancel_verification(p->context);
   r->stage=r->verify_cancel_result==1?TL_VERIFY_EXHAUSTED:TL_VERIFY_CANCEL_UNKNOWN;
   r->replay_forbidden=1;
  }else r->stage=TL_VERIFYING;
  return 1;
 }
 if(verification!=TL_VERIFY_DONE){r->stage=TL_VERIFY_FAILED;r->replay_forbidden=1;return 1;}
 if(!same_admission(p,ui,request)){r->stage=TL_REVOKED;r->eligibility_lost=1;return 1;}
 void*h=p->load_verified(p->context);
 if(!h){r->stage=TL_LOAD_FAILED;r->replay_forbidden=1;return 1;}
 tl_entry entry=p->resolve_verified_entry(p->context,h);
 if(!entry){
  if(p->resolve_revoked(p->context)){r->stage=TL_REVOKED;r->eligibility_lost=1;}
  else{r->stage=TL_RESOLVE_FAILED;r->replay_forbidden=1;}
 }
 else if(!same_admission(p,ui,request)){r->stage=TL_REVOKED;r->eligibility_lost=1;}
 else{
  int prior_known=r->known_core;r->entered=1;r->entry_calls++;
  r->entry_result=(uint32_t)entry(h,ui);r->stage=TL_ENTRY_RETURNED;
  if(r->entry_result==0){r->known_core=1;r->accepted_activation=request;}
  else if(r->entry_result==TL_ENTRY_ACTIVATION_PENDING){
   r->known_core=1;if(r->queue_activation!=request){r->queue_activation=request;r->queue_results=0;}r->queue_results++;
  }else if(r->entry_result==TL_ENTRY_PREPARING&&!prior_known){
   r->preparing_results++;
   if(r->preparing_results==TL_MAX_PREPARING_RESULTS){
    r->cancel_calls++;r->cancel_result=(uint32_t)entry(h,0);
    r->stage=r->cancel_result==TL_ENTRY_CANCELLED?TL_PREPARING_EXHAUSTED:TL_CANCEL_UNKNOWN;
    r->replay_forbidden=1;
   }
  }else if(r->entry_result==TL_ENTRY_SAFE_BUSY&&!prior_known&&!r->preparing_results){r->safe_busy_results++;}
  else r->replay_forbidden=1;
 }
 entry=0;r->closed=1;
 if(p->close_owned(p->context,h)){r->close_uncertain=1;r->replay_forbidden=1;}
 if(r->stage==TL_ENTRY_RETURNED&&!r->close_uncertain&&!r->replay_forbidden){
  if(r->entry_result==TL_ENTRY_ACTIVATION_PENDING)r->stage=r->queue_results<TL_MAX_ACTIVATION_RESULTS?TL_ACTIVATION_PENDING:TL_ACTIVATION_EXHAUSTED;
  else if(r->entry_result==TL_ENTRY_PREPARING)r->stage=TL_PREPARING;
  else if(r->entry_result==TL_ENTRY_SAFE_BUSY)r->stage=r->safe_busy_results<TL_MAX_SAFE_BUSY_RESULTS?TL_SAFE_BUSY:TL_BUSY_EXHAUSTED;
 }
 return 1;
}
