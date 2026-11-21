/* Host ASan/UBSan test for hash-cycle-free A7TBM001 optional autoloader. */
#include "../startup-owner/autoload/optional_loader.h"
#include "../startup-owner/autoload/boot_manifest.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static struct {
 uint32_t request;unsigned ui,allowed,activation_calls,eligible_calls,verify_calls,
 loads,resolves,entries,closes,verify_cancels,entry_cancels,caller_refs;
 unsigned verify_more,verify_result,verify_cancel_result,load_fail,resolve_fail,
 close_fail,revoke_eligible_at,change_activation_at,change_ui_at_activation,resolve_revoked;
 int entry_result,cancel_result;
}f;
static unsigned cases,checks;
static void ck(int b){checks++;assert(b);}
static int activation(void*x,uint32_t*ui,uint32_t*request){ck(x==&f);f.activation_calls++;if(f.change_activation_at&&f.activation_calls==f.change_activation_at)f.request+=8;if(f.change_ui_at_activation&&f.activation_calls==f.change_ui_at_activation)f.ui++;*ui=f.ui;*request=f.request;return f.allowed;}
static int eligible(void*x,uint32_t*ui){ck(x==&f);f.eligible_calls++;*ui=f.ui;return f.allowed&&f.eligible_calls!=f.revoke_eligible_at;}
static int verify(void*x){ck(x==&f);f.verify_calls++;return f.verify_calls<=f.verify_more?TL_VERIFY_MORE:(int)f.verify_result;}
static void*load(void*x){ck(x==&f);f.loads++;if(f.load_fail)return 0;ck(!f.caller_refs);f.caller_refs=1;return &f;}
static int entry(void*h,uint32_t ui){ck(h==&f&&f.caller_refs==1);if(!ui){f.entry_cancels++;return f.cancel_result;}ck(ui==f.ui);f.entries++;return f.entry_result;}
static tl_entry resolve(void*x,void*h){ck(x==&f&&h==&f&&f.caller_refs==1);f.resolves++;return f.resolve_fail?0:entry;}
static int close_owned(void*x,void*h){ck(x==&f&&h==&f&&f.caller_refs==1);f.closes++;f.caller_refs=0;return f.close_fail;}
static int cancel_verify(void*x){ck(x==&f);f.verify_cancels++;return(int)f.verify_cancel_result;}
static int resolve_revoked(void*x){ck(x==&f);return(int)f.resolve_revoked;}
static struct tl_port port={&f,eligible,verify,load,resolve,close_owned,cancel_verify,activation,resolve_revoked};
static void reset(struct tl_report*r){memset(&f,0,sizeof f);f.allowed=1;f.ui=392;f.request=13;f.verify_result=1;f.verify_cancel_result=1;f.cancel_result=TL_ENTRY_CANCELLED;tl_init(r);}
static int step(struct tl_report*r){int rc=tl_step(r,&port);ck(!f.caller_refs);return rc;}
static void new_act(void){f.request+=8;}
static void terminal(struct tl_report*r){unsigned v=f.verify_calls,e=f.entries,l=f.loads,c=f.closes;new_act();for(unsigned i=0;i<20;i++)ck(step(r)==0);ck(v==f.verify_calls&&e==f.entries&&l==f.loads&&c==f.closes);}
int main(void){struct tl_report r;
 /* Also test A7TBM001 128-byte boot manifest framing */
 struct touch_boot_manifest m;memset(&m,0,sizeof m);
 memcpy(m.magic,"A7TBM001",8);m.abi=1;m.bytes=128;m.build=0x3111fe07u;m.entry_api=1;m.core_bytes=161576;m.entry_offset=143856;
 m.core_sha256[0]=0x27;m.entry_anchor[0]=0xf0;m.owner_sha256[0]=0xc6;m.installation[0]=0x48;
 ck(tbm_validate(&m)==1);
 m.entry_api=0;ck(tbm_validate(&m)==0);m.entry_api=1;cases++;

 reset(&r);f.allowed=0;ck(step(&r)==0&&!r.attempted&&!f.eligible_calls&&!f.verify_calls);f.allowed=1;ck(step(&r)==1&&r.known_core&&r.accepted_activation==13&&f.entries==1);cases++;
 unsigned v=f.verify_calls,n=f.eligible_calls;for(unsigned i=0;i<100;i++)ck(step(&r)==0);ck(f.entries==1&&f.verify_calls==v&&f.eligible_calls==n);cases++;
 new_act();ck(step(&r)==1&&f.entries==2&&r.activation_reentries==1&&r.accepted_activation==21);v=f.verify_calls;for(unsigned i=0;i<20;i++)ck(step(&r)==0);ck(f.verify_calls==v);cases++;
 f.request=13;ck(step(&r)==0&&f.entries==2);f.request=1;ck(step(&r)==0&&f.entries==2);cases++;
 reset(&r);f.request=1;ck(step(&r)==1&&r.accepted_activation==1);f.request=13;ck(step(&r)==1&&r.accepted_activation==13&&r.activation_reentries==1);cases++;
 reset(&r);f.entry_result=TL_ENTRY_ACTIVATION_PENDING;
 for(unsigned i=0;i<50;i++)ck(step(&r)==1);
 ck(r.known_core&&r.stage==TL_ACTIVATION_EXHAUSTED&&r.queue_results==50&&f.closes==50);v=f.verify_calls;ck(step(&r)==0&&f.verify_calls==v);
 new_act();ck(step(&r)==1&&r.stage==TL_ACTIVATION_PENDING&&r.queue_results==1&&r.activation_reentries==1);f.entry_result=0;ck(step(&r)==1&&r.accepted_activation==21&&r.stage==TL_ENTRY_RETURNED);ck(step(&r)==0);cases++;
 reset(&r);ck(step(&r)==1);new_act();f.entry_result=TL_ENTRY_ACTIVATION_PENDING;ck(step(&r)==1&&r.queue_results==1);f.allowed=0;v=f.verify_calls;ck(step(&r)==0&&f.verify_calls==v);f.allowed=1;f.entry_result=0;ck(step(&r)==1&&r.accepted_activation==21);cases++;
 const int unknown[]={1,-23,0x7002,TL_ENTRY_CANCELLED};
 for(unsigned i=0;i<sizeof unknown/sizeof unknown[0];i++){reset(&r);f.entry_result=unknown[i];ck(step(&r)==1&&r.replay_forbidden);terminal(&r);cases++;}
 for(unsigned i=0;i<2;i++){reset(&r);ck(step(&r)==1);new_act();f.entry_result=i?TL_ENTRY_PREPARING:TL_ENTRY_SAFE_BUSY;ck(step(&r)==1&&r.replay_forbidden&&r.known_core);terminal(&r);cases++;}
 for(unsigned i=0;i<3;i++){reset(&r);f.entry_result=i==0?0:i==1?TL_ENTRY_ACTIVATION_PENDING:TL_ENTRY_PREPARING;f.close_fail=1;ck(step(&r)==1&&r.close_uncertain&&r.replay_forbidden&&f.closes==1);terminal(&r);cases++;}
 reset(&r);f.entry_result=TL_ENTRY_PREPARING;for(unsigned i=0;i<1024;i++)ck(step(&r)==1);new_act();for(unsigned i=0;i<1024;i++)ck(step(&r)==1);
 ck(r.stage==TL_PREPARING_EXHAUSTED&&r.preparing_results==2048&&f.entry_cancels==1&&r.cancel_result==TL_ENTRY_CANCELLED&&f.closes==2048);terminal(&r);cases++;
 reset(&r);f.entry_result=TL_ENTRY_PREPARING;f.cancel_result=0x7045;r.preparing_results=2047;r.stage=TL_PREPARING;r.attempted=1;ck(step(&r)==1&&r.stage==TL_CANCEL_UNKNOWN&&r.replay_forbidden);terminal(&r);cases++;
 reset(&r);f.verify_more=3;ck(step(&r)==1&&r.stage==TL_VERIFYING);new_act();ck(step(&r)==1&&r.stage==TL_VERIFYING);ck(step(&r)==1&&r.stage==TL_VERIFYING);ck(step(&r)==1&&r.accepted_activation==21&&f.entries==1);cases++;
 reset(&r);f.verify_more=1000;for(unsigned i=0;i<128;i++)ck(step(&r)==1);ck(r.stage==TL_VERIFY_EXHAUSTED&&f.verify_cancels==1&&!f.entries);terminal(&r);cases++;
 reset(&r);f.verify_more=1000;f.verify_cancel_result=0;for(unsigned i=0;i<128;i++)ck(step(&r)==1);ck(r.stage==TL_VERIFY_CANCEL_UNKNOWN&&f.verify_cancels==1);terminal(&r);cases++;
 reset(&r);f.entry_result=TL_ENTRY_SAFE_BUSY;for(unsigned i=0;i<25;i++)ck(step(&r)==1);new_act();for(unsigned i=0;i<25;i++)ck(step(&r)==1);ck(r.stage==TL_BUSY_EXHAUSTED&&r.safe_busy_results==50);terminal(&r);cases++;
 for(unsigned phase=0;phase<2;phase++)for(unsigned prior=0;prior<3;prior++){
  reset(&r);if(prior){f.entry_result=prior==1?0:TL_ENTRY_PREPARING;ck(step(&r)==1);new_act();}
  unsigned entries=f.entries;f.entry_result=0;f.revoke_eligible_at=f.eligible_calls+(phase?3:2);
  ck(step(&r)==1&&r.stage==TL_REVOKED&&f.entries==entries&&!r.replay_forbidden);
  ck(r.known_core==(prior==1)&&r.preparing_results==(prior==2));
  v=f.verify_calls;f.revoke_eligible_at=0;ck(step(&r)==0&&f.verify_calls==v);
  new_act();ck(step(&r)==1&&r.accepted_activation==f.request&&f.entries==entries+1&&r.preparing_results==(prior==2));cases++;
 }
 reset(&r);f.change_activation_at=3;ck(step(&r)==1&&r.stage==TL_REVOKED&&!f.entries);ck(step(&r)==1&&r.accepted_activation==21&&f.entries==1);cases++;
 reset(&r);f.change_ui_at_activation=3;ck(step(&r)==1&&r.stage==TL_REVOKED&&!f.entries);ck(step(&r)==0);new_act();ck(step(&r)==1&&r.ui_tid==393&&f.entries==1);cases++;
 reset(&r);f.revoke_eligible_at=3;f.close_fail=1;ck(step(&r)==1&&r.stage==TL_REVOKED&&!f.entries&&r.close_uncertain&&r.replay_forbidden);terminal(&r);cases++;
 reset(&r);f.resolve_fail=1;f.resolve_revoked=1;ck(step(&r)==1&&r.stage==TL_REVOKED&&!f.entries&&f.closes==1&&!r.replay_forbidden);ck(step(&r)==0);new_act();f.resolve_fail=f.resolve_revoked=0;ck(step(&r)==1&&r.accepted_activation==21&&f.entries==1);cases++;
 for(unsigned mode=0;mode<3;mode++){reset(&r);if(mode==0)f.verify_result=0;else if(mode==1)f.load_fail=1;else f.resolve_fail=1;ck(step(&r)==1&&r.stage==(mode==0?TL_VERIFY_FAILED:mode==1?TL_LOAD_FAILED:TL_RESOLVE_FAILED)&&r.replay_forbidden);terminal(&r);cases++;}
 for(unsigned mode=0;mode<3;mode++){reset(&r);f.request=mode==0?0:mode==1?5:18;ck(step(&r)==0&&!f.eligible_calls&&!f.verify_calls);cases++;}
 reset(&r);f.ui=1;ck(step(&r)==0&&!f.eligible_calls);cases++;
 printf("R5_POLICY_TEST cases=%u checks=%u failures=0 report=%zu\n",cases,checks,sizeof r);return 0;
}
