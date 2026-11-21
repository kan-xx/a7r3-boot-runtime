#include "barrier_adapter.h"
extern void*dlsym(void*,const char*),*dlvsym(void*,const char*,const char*);
struct info{const char*path;void*base;const char*symbol;void*address;};extern int dladdr(const void*,struct info*);
extern int nb_anchors(struct bp_report*),nb_policy(uint32_t*),bp_warmup(const struct bp_ports*,struct bp_report*);extern void nb_delay(void),nb_cold_mode(unsigned);
static struct np_context*platform;static struct fb_barrier_status status;static unsigned terminal_failure;
static int eq(const void*a,const void*b,unsigned n){const uint8_t*p=a,*q=b;unsigned v=0;while(n--)v|=*p++^*q++;return !v;}
int fb_barrier_init(struct np_context*p){
 if(status.initialized||!p||np_check(p))return -1;
 static const uint8_t anchor[16]={0x2d,0xe9,0xf0,0x4f,0x10,0xf0,0x02,0x03,0x85,0xb0,0x04,0x46,0xf2,0x46,0x00,0xaf};
 void*io=dlvsym(p->refs[1],"ioctl","GLIBC_2.4"),*err=dlvsym(p->refs[1],"__errno_location","GLIBC_2.4"),*id=dlsym(p->refs[0],"osal_dynamic_id");struct info d={0};uint8_t actual[16];
 if(!io||!err||!id||!dladdr(id,&d)||(uint32_t)d.base!=p->s.osal_base||(uint32_t)id-(uint32_t)d.base!=0x4841||np_read(p,(uint32_t)id&~1u,actual,16)||!eq(actual,anchor,16))return -1;
 struct nb_config cfg={p,io,err,id,nb_policy,nb_delay};if(nb_bind(&cfg))return -1;platform=p;status.initialized=1;return 0;
}
int fb_barrier_run(void*ignored,struct bp_report*r){
 (void)ignored;if(!status.initialized||!r||terminal_failure||status.runs==UINT32_MAX||np_check(platform))return -1;uint8_t*b=(void*)r;for(unsigned i=0;i<sizeof *r;i++)b[i]=0;r->pid=platform->s.pid;r->tid=platform->s.worker_tid;status.runs++;
 if(nb_anchors(r)){r->error=202;return -1;}uint32_t notify[4];nb_cold_mode(1);int rc=nb_policy(notify);nb_cold_mode(0);if(rc){r->error=203;return -1;}
 if(!(notify[0]|notify[1]|notify[2]|notify[3])){
  /* lo_tick admits one barrier attempt per parked power epoch. A successful
   * warmup belongs to that RTOS incarnation, not the Linux process lifetime.
   * A fresh verified zero singleton may be initialized once in this call.
   * Any uncertain outcome is terminal, including across later epochs. */
  if(status.warmup_attempted==UINT32_MAX){terminal_failure=1;r->error=204;return -1;}
  status.warmup_attempted++;uint8_t*w=(void*)&status.warmup;for(unsigned i=0;i<sizeof status.warmup;i++)w[i]=0;status.warmup.pid=platform->s.pid;status.warmup.tid=platform->s.worker_tid;status.warmup.anchors=r->anchors;
  nb_cold_mode(1);status.warmup_result=bp_warmup(nb_ports(),&status.warmup);nb_cold_mode(0);if(status.warmup_result){terminal_failure=1;r->error=205;return -1;}
 }
 int result=bp_run(nb_ports(),r);if(result)terminal_failure=1;return result;
}
const struct fb_barrier_status*fb_barrier_status(void){return &status;}
