#include "probe.h"
static int eq(const void*a,const void*b,unsigned n){const uint8_t*x=a,*y=b;uint32_t d=0;while(n--)d|=*x++^*y++;return !d;}
static void copy(void*a,const void*b,unsigned n){uint8_t*x=a;const uint8_t*y=b;while(n--)*x++=*y++;}
static int fail(struct bp_report*r,unsigned e,int rc){r->error=e;r->last_rc=(uint32_t)rc;r->retained_ids=(r->reply_sid?1:0)+(r->source_sid?1:0);return -1;}
static int create(const struct bp_ports*p,struct bp_report*r,unsigned kind,uint32_t*out){struct{uint32_t a,id,b;}v={0x13579bdf,0,0x2468ace0};int rc=p->id(kind,0xdc,(uintptr_t)&v.id);*out=v.id;if(rc)return fail(r,2,rc);if(v.a!=0x13579bdf||v.b!=0x2468ace0||(v.id>>16)!=0xdc||(v.id&0x7fff)<0x6000||(v.id&0x7fff)>=0x7000||!!(v.id&0x8000)!=(kind==0x29))return fail(r,3,0);return 0;}
static int poll(const struct bp_ports*p,struct bp_report*r,uint32_t source,const uint32_t*expect){
 for(unsigned i=0;i<100;i++){void*m=0;r->receive_calls++;int rc=p->recv(r->reply_sid,&m,0);r->last_rc=(uint32_t)rc;
  if(rc==-1022&&!m){p->delay();continue;}r->held_message=(uint32_t)(uintptr_t)m;r->held_destination=r->reply_sid;if(rc||!m||((uintptr_t)m&3))return fail(r,6,rc);
  int n=p->size(m);r->reply_capacity=(uint32_t)n;if(n<32||n>8192)return fail(r,7,n);
  r->reply_source=((uint32_t*)m)[-1];copy(r->reply,m,32);int good=r->reply_source==source&&eq(m,expect,32);
  r->free_calls++;rc=p->free(r->reply_sid,m);if(rc)return fail(r,8,rc);r->held_message=r->held_destination=0;if(!good)return fail(r,9,0);return 0;
 }return fail(r,10,-1022);
}
static int empty(const struct bp_ports*p,struct bp_report*r){void*m=0;r->receive_calls++;int rc=p->recv(r->reply_sid,&m,0);if(rc==-1022&&!m)return 0;r->held_message=(uint32_t)(uintptr_t)m;r->held_destination=r->reply_sid;return fail(r,11,rc);}
static int send(const struct bp_ports*p,struct bp_report*r,uint32_t dest,uint32_t source,const uint32_t*frame){void*m=0;int rc=p->alloc(dest,&m,32,0);r->held_message=(uint32_t)(uintptr_t)m;r->held_destination=dest;if(rc||!m||((uintptr_t)m&3))return fail(r,4,rc);((uint32_t*)m)[-1]=source;copy(m,frame,32);r->send_calls++;rc=p->send(dest,m);if(rc)return fail(r,5,rc);r->held_message=r->held_destination=0;return 0;}
int bp_run(const struct bp_ports*p,struct bp_report*r){
 r->abi=1;r->bytes=sizeof *r;r->stage=1;
 if(p->policy(r->before))return fail(r,1,0);
 r->stage=2;if(create(p,r,0x2b,&r->reply_sid)||create(p,r,0x29,&r->source_sid))return -1;
 const uint32_t loop[8]={0x31425041,1,2,3,4,5,6,7};r->stage=3;
 if(send(p,r,r->reply_sid,r->reply_sid,loop)||poll(p,r,r->reply_sid,loop)||empty(p,r))return -1;r->loop_ok=1;
 uint32_t notify[4];if(p->policy(notify)||!eq(notify,r->before,16))return fail(r,12,0);
 /* Exactly one recognized rejection request. Subtypes0/1 would mutate original
  * notification configuration and are NEVER emitted by this component. */
 const uint32_t q[8]={r->reply_sid,0xa0a0a0a0,0x00200001,20,32,0x02052004,0x0001000c,2};
 const uint32_t a[8]={0,0xa0a0a0a0,0x00200001,20,32,0x82052004,0x0001000c,0xe002};
 r->stage=4;if(send(p,r,0x58003f,r->source_sid,q))return -1;
 r->stage=5;if(poll(p,r,0x58003f,a))return -1;r->barrier_ok=1;
 r->stage=6;if(empty(p,r)||p->policy(r->after)||!eq(r->before,r->after,16))return fail(r,13,0);r->notify_unchanged=1;
 /* Original response sender has no further access to this destination after
  * successful send. No callback, code or payload pointer was handed to it.
  * This does not authorize releasing any sound/DMM resource. */
 r->stage=7;int rc;r->delete_calls++;rc=p->id(0x4b,0,r->reply_sid);if(rc)return fail(r,14,rc);r->reply_sid=0;
 r->delete_calls++;rc=p->id(0x49,0,r->source_sid);if(rc)return fail(r,15,rc);r->source_sid=0;r->retained_ids=0;r->stage=8;return 0;
}
