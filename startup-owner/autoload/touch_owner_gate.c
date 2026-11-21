#include "touch_owner_gate.h"
int touch_owner_gate(const struct touch_owner_now*a,const struct touch_owner_now*b,
                     const struct lo_status*s){
 if(!a||!b||!s)return 0;
 const uint8_t*x=(const uint8_t*)a,*y=(const uint8_t*)b;
 for(unsigned i=0;i<sizeof*a;i++)if(x[i]!=y[i])return 0;
 if(a->phase!=22||a->ready!=1||a->stop||a->error||a->final_requested||
    a->ingress_error||a->prepared!=1||a->owner_error||a->bootstrap_error||
    a->bootstrap_ready!=1||a->ui_tid<2)return 0;
 uint32_t gen=a->request>>3;
 int initial=a->request==1&&a->bootstrap_state==3;
 int active=(a->request&7)==LO_ACT&&gen&&a->act_claim==gen&&
            (a->bootstrap_state==3||a->bootstrap_state==4);
 if(!initial&&!active)return 0;
 if(s->error||s->audio.phase!=LP_ACTIVE||s->menu.control.phase!=LP_ACTIVE||
    (s->audio.word&3)||(s->menu.control.word&3))return 0;
 if(active&&(s->event!=LO_ACT||s->generation!=gen||s->worker_generation!=gen||
             s->act_claim!=gen))return 0;
 if(initial&&s->bootstrap_state!=3)return 0;
 return 1;
}
