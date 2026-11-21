#include "ports.h"
_Static_assert(sizeof(void*)==4,"ARM32 ABI");
static struct nb_config q;static struct nb_status s;
static int bad(unsigned e){if(!s.error)s.error=e;if(s.reply_sid||s.source_sid)s.retained=1;return -4095;}
static int ready(void){return s.initialized&&!s.error&&np_check(q.platform)==0;}
static int call(unsigned op,void*arg){
 if(!ready())return bad(1);s.calls++;s.last_op=op;
 int r=q.ioctl_one(q.platform->s.duplicate_fd,op,arg);
 if(r==-1){int e=*q.errno_address();r=e>0&&e<=4095?-e:-4095;}
 s.last_rc=(uint32_t)r;return r;
}
static int pointer(const void*p,unsigned bytes){uint32_t a=(uint32_t)(uintptr_t)p;const struct np_status*n=&q.platform->s;return p&&!(a&3)&&a>=n->pool_lo&&a-n->pool_lo>=12&&a<=n->pool_hi&&bytes<=n->pool_hi-a;}
static int id(unsigned op,unsigned domain,uintptr_t value){
 if(!ready())return bad(2);
 if(op==0x29){if(domain!=0xdc||!value||s.source_sid)return bad(3);int r=q.local_id(op,domain,value);s.source_sid=*(uint32_t*)value;if(r)s.retained=1;return r;}
 if(op==0x49){if(domain||!s.source_sid||value!=s.source_sid)return bad(4);int r=q.local_id(op,domain,value);if(!r)s.source_sid=0;else s.retained=1;return r;}
 if(op!=0x2b&&op!=0x4b)return bad(5);
 if(op==0x2b&&(domain!=0xdc||!value||s.reply_sid))return bad(6);
 if(op==0x4b&&(domain||!s.reply_sid||value!=s.reply_sid))return bad(7);
 uint32_t inner[3]={op,domain,value},arg[2]={0,(uint32_t)(uintptr_t)inner};int r=call(0x8000000c,arg);
 if(op==0x2b)s.reply_sid=*(uint32_t*)value;else if(!r)s.reply_sid=0;
 if(r)s.retained=1;return r;
}
static int alloc(unsigned sid,void**out,unsigned bytes,unsigned wait){
 if(!out||*out||bytes!=32||wait!=0||(sid!=s.reply_sid&&sid!=0x58003f))return bad(8);
 uint32_t inner[3]={(uint32_t)(uintptr_t)out,bytes,0},arg[2]={sid,(uint32_t)(uintptr_t)inner};int r=call(0x8000000a,arg);
 if(r){if(*out)s.retained=1;return r;}if(!ready()||!pointer(*out,bytes)){s.retained=1;return bad(9);}return 0;
}
static int send(unsigned sid,void*p){if((sid!=s.reply_sid&&sid!=0x58003f)||!pointer(p,32))return bad(10);uint32_t arg[2]={sid,(uint32_t)(uintptr_t)p};int r=call(0x80000004,arg);if(r)s.retained=1;return r;}
static int recv(unsigned sid,void**out,int timeout){
 if(!s.reply_sid||sid!=s.reply_sid||!out||*out||timeout!=0)return bad(11);
 uint32_t inner[2]={(uint32_t)(uintptr_t)out,0},arg[2]={sid,(uint32_t)(uintptr_t)inner};int r=call(0x80000007,arg);
 if(r){if(*out)s.retained=1;return r;}if(!ready()||!pointer(*out,32)){s.retained=1;return bad(12);}return 0;
}
static int free_message(unsigned sid,void*p){if(!s.reply_sid||sid!=s.reply_sid||!pointer(p,32))return bad(13);uint32_t arg[2]={sid,(uint32_t)(uintptr_t)p};int r=call(0x8000000b,arg);if(r)s.retained=1;return r;}
static int message_size(void*p){uint8_t size;if(!ready()||!pointer(p,32))return bad(14);/* Sony UIPC PFN mapping rejects /proc/self/mem access. Read only the header inside this exact owned, range-checked message, as the original osal_msg_size does. */size=*((const volatile uint8_t*)p-8);int n=size?(int)size*32-12:20;if(n<32||!pointer(p,(unsigned)n))return bad(15);return n;}
static int policy(uint32_t*p){return ready()?q.policy(p):bad(16);}
static void delay(void){q.delay();}
static const struct bp_ports ports={id,alloc,send,free_message,recv,message_size,policy,delay};
int nb_bind(const struct nb_config*c){if(s.initialized||!c||!c->platform||!c->ioctl_one||!c->errno_address||!c->local_id||!c->policy||!c->delay||np_check(c->platform))return -1;q=*c;s.initialized=1;return 0;}
const struct bp_ports*nb_ports(void){return &ports;}
const struct nb_status*nb_report(void){return &s;}
