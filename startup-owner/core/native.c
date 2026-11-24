#include "owner_report_cache.h"
#include "../autoload/touch_owner_gate.h"
#include "../autoload/native_loader.h"
#include "../bootstrap/bootstrap_gate.h"
#include "../bundle/bundle.h"
#include "../bundle/barrier_adapter.h"
#include "../platform/platform.h"
#include "pthread_identity.h"
#include "registration.h"
#include "sem_port.h"
#include "../lifecycle/completion.h"
#include "../../boot-guard/transaction.h"
#include "sha256_local.h"
#include "identity.h"
#include "ready_record.h"
#include "../../exit-bridge/loader.h"
_Static_assert(LO_AUDIO_BUILD==AP_BUILD,"coordinator/audio build contract");
_Static_assert(LO_MENU_BUILD==MP_BUILD,"coordinator/menu build contract");
extern long syscall(long,...);
extern int pthread_create(unsigned long*,const void*,void*(*)(void*),void*),pthread_join(unsigned long,void**);
extern void *dlopen(const char*,int),*dlsym(void*,const char*),*dlvsym(void*,const char*,const char*);
struct info{const char*path;void*base;const char*symbol;void*address;};extern int dladdr(const void*,struct info*);
#define EXPORT __attribute__((visibility("default")))
static struct np_context platform;
static struct bg_control bootstrap;
static struct fb_context bundle;
static struct lo_status lifecycle;
static int failure_probe_rc=-999;
static unsigned disabled_reported;
static uint32_t final_requested,final_entered,final_done,finalize_claim;
static struct rl_control lease;
static struct sp_control sem_port;
static struct lc_control channel;
static uint32_t phase,error,claimed,created,stop,exited,ready,worker_started;
static struct owner_report_cache report_cache;
static int touch_owner_eligible(void*,uint32_t*);
static int touch_owner_activation(void*,uint32_t*,uint32_t*);
static struct tln_context touch_loader_context={.platform=&platform,.eligible=touch_owner_eligible,.activation=touch_owner_activation};
static struct tl_report touch_loader_report;
static uint32_t touch_loader_last_ms;
_Static_assert(sizeof(struct tl_report)<=128,"optional touch report reserved bytes");
static unsigned long thread;static void*self_pin,*db_pin;
static int(*ioctl_fn)(int,unsigned,void*);static int*(*errno_fn)(void);
static uint32_t(*find_fn)(unsigned,unsigned);
static uint32_t pid,worker_tid,descriptor,sem_calls;
static unsigned char runtime_db_hash[32];
static struct ar_ready_status ready_status,failure_status,report_status;
static uint32_t ld(const uint32_t*p){return __atomic_load_n(p,__ATOMIC_ACQUIRE);}
static void st(uint32_t*p,uint32_t v){__atomic_store_n(p,v,__ATOMIC_RELEASE);}
static int eq(const void*a,const void*b,unsigned n){const unsigned char*p=a,*q=b;unsigned v=0;while(n--)v|=*p++^*q++;return !v;}
static int same(const char*a,const char*b){if(!a||!b)return 0;while(*a&&*a==*b){a++;b++;}return *a==*b;}
static void copy(void*a,const void*b,unsigned n){unsigned char*p=a;const unsigned char*q=b;while(n--)*p++=*q++;}
static uint32_t tid(void*x){(void)x;return syscall(224);}
static void pause20(void){long t[2]={0,20000000};syscall(162,t,0);}
void nap_progress(unsigned v){st(&phase,v);}
static void write_evidence(const char*,const void*,unsigned);
static int failure(unsigned e){uint32_t zero=0;if(__atomic_compare_exchange_n(&error,&zero,e,0,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE)){st(&phase,100);bg_fail(&bootstrap,e);ar_write_failure(READY_DIR,installation,runtime_db_hash,OWNER_BUILD,pid,e,&failure_status);}return -1;}
static void write_evidence(const char*path,const void*bytes,unsigned size){int f=syscall(5,path,AR_CREATE_EXCLUSIVE,0600);if(f<0)return;syscall(4,f,bytes,size);syscall(118,f);syscall(6,f);}
static void entry_evidence(unsigned event){uint32_t r[8]={0x32534f41,OWNER_BUILD,(unsigned)syscall(20),tid(0),event,ld(&phase),ld(&error),0};write_evidence(ENTRY_RECORD,r,sizeof r);}
static int hash_db_elf(const char*path,unsigned char out_sha[32]){
 static const unsigned char elf_arm32[7]={0x7f,'E','L','F',1,1,1};
 int f=syscall(5,path,0x80000,0);if(f<0)return -1;
 struct sha256 h;unsigned char b[4096],hdr[52]={0};sha_init(&h);unsigned total=0;int good=1;
 while(total<=1048576u){
  long n=syscall(3,f,b,sizeof b);if(n<0){good=0;break;}if(!n)break;
  for(unsigned i=0;i<(unsigned)n&&total+i<52u;i++)hdr[total+i]=b[i];
  sha_add(&h,b,(unsigned)n);total+=(unsigned)n;
 }
 sha_end(&h,out_sha);if(syscall(6,f))good=0;
 unsigned e_type=hdr[16]|((unsigned)hdr[17]<<8),e_machine=hdr[18]|((unsigned)hdr[19]<<8);
 return (good&&total>=52u&&total<=1048576u&&eq(hdr,elf_arm32,7)&&e_type==3u&&e_machine==40u)?0:-1;
}
static int read_words(void*x,uint32_t a,uint32_t*out,uint32_t n){(void)x;return np_read(&platform,a,out,n*4);}
static int single_ioctl(void*x,int fd,uint32_t op,void*arg){(void)x;if(np_check(&platform)||fd!=platform.s.duplicate_fd)return -4095;return ioctl_fn(fd,op,arg);}
static int errno_value(void*x){(void)x;return *errno_fn();}
static int sem_check(void*x){(void)x;return np_check(&platform);}
static int sem_release_check(void*x){(void)x;return np_check_release(&platform);}
static uint32_t sem_node(void*x){(void)x;return lease.status.node_sem;}
static int sem_held(void*x,uint32_t s){(void)x;return s==SP_GLOBAL?lease.status.global_held:(s==lease.status.node_sem&&lease.status.node_held);}
static int sem_invoke(void*x,uint32_t op,uint32_t sid){(void)x;uint32_t arg[2]={sid,0};sem_calls++;int r=ioctl_fn(platform.s.duplicate_fd,op,arg);if(r==-1){int e=errno_value(0);r=e>0&&e<=4095?-e:-4095;}return r;}
static int try_sem(void*x,uint32_t s){(void)x;return sp_acquire(&sem_port,s);}
static int signal_sem(void*x,uint32_t s){(void)x;return sp_release(&sem_port,s);}
static uint32_t find_entry(void*x,unsigned id,unsigned mask){(void)x;return find_fn(id,mask);}
static int add_reference(void*x,unsigned d,unsigned marker){
 (void)x;int rc=((int(*)(unsigned,unsigned))0xbd19)(d,marker);
 /* Original bd18 may allocate a reference node outside the pre-call maps
  * snapshot (for example after brk grows the heap). Recheck the complete maps,
  * worker identity, original fd/duplicate, uconf and exact pool identity before
  * registration reads the newly published node. This runs once, under both
  * registry semaphores, after rl_acquire has claimed attempted/add_calls.
  * Never replay bd18 or adopt a changed fd/pool; any check failure is terminal.
  * A post-check read miss still fails normally; np_read is unchanged. */
 if(np_check(&platform))return -4095;
 return rc;
}
static int snapshot(void*x,unsigned command,struct lo_im_state*out){(void)x;struct rl_state r;int rc=rl_snapshot(&lease,command,&r);if(rc)return rc;*out=(struct lo_im_state){r.pid,r.descriptor,r.module_id,r.type,r.state,r.pending};return 0;}
static int complete(void*x,unsigned command,unsigned id){(void)x;return lc_complete(&channel,command,id);}
static int qualify(void){
 if(np_open(&platform))return failure(1);if(pid!=platform.s.pid)return failure(1);worker_tid=platform.s.worker_tid;
 if(worker_tid==pid||np_check(&platform))return failure(2);
 ioctl_fn=dlvsym(platform.refs[1],"ioctl","GLIBC_2.4");errno_fn=dlvsym(platform.refs[1],"__errno_location","GLIBC_2.4");if(!ioctl_fn||!errno_fn)return failure(3);
 if(hash_db_elf("/usr/lib/libIMDB.so",runtime_db_hash))return failure(4);
 db_pin=dlopen("/usr/lib/libIMDB.so",6);if(!db_pin)return failure(5);find_fn=dlsym(db_pin,"IMDB_find_entry");struct info d={0},dd={0};unsigned char b[128];
 if(!find_fn||!dladdr(find_fn,&d)||!d.base||(!same(d.path,"/usr/lib/libIMDB.so")&&!same(d.path,"//usr/lib/libIMDB.so"))||np_read(&platform,(uint32_t)find_fn&~1u,b,16))return failure(6);
 descriptor=find_fn(0xfffe,1);if(!descriptor||!dladdr((const void*)(uintptr_t)descriptor,&dd)||dd.base!=d.base||np_read(&platform,0xbd18,b,sizeof ref_anchor)||!eq(b,ref_anchor,sizeof ref_anchor))return failure(7);
 uint32_t words[11];if(read_words(0,descriptor,words,11)||words[0]!=0x20000003||words[1]!=4||words[2]!=1||words[3]!=0xfffe)return failure(8);
 for(unsigned i=0;i<7;i++){unsigned n=0;while(db_strings[i][n])n++;n++;if(n>sizeof b||np_read(&platform,words[i+4],b,n)||!eq(b,db_strings[i],n))return failure(9);}
 struct rl_config r={.port={0,tid,read_words,try_sem,signal_sem,find_entry,add_reference},.pid=pid,.worker_tid=worker_tid,.descriptor=descriptor,.handle=(uint32_t)self_pin,.target_mask=1};copy(r.descriptor_words,words,sizeof words);
 struct lc_config q={0,tid,single_ioctl,errno_value,&platform.s.duplicate_fd,worker_tid,platform.s.pool_lo,platform.s.pool_hi};
 if(lc_init(&channel,&q)||rl_init(&lease,&r))return failure(10);struct sp_port sp={0,sem_check,sem_release_check,sem_invoke,sem_node,sem_held};sp_init(&sem_port,&sp);return 0;
}
static uint32_t now_ms(void){long t[2];if(syscall(263,1,t)||t[0]<0||t[1]<0||t[1]>=1000000000)return 0;return (uint32_t)t[0]*1000u+(uint32_t)t[1]/1000000u;}
/* Optional loader admission runs only on this existing worker. Before the
 * original worker-only lo_report, exclude unprepared/unfinished bootstrap;
 * cfg.port.tid must never be called through an uninitialized LO config. */
static void touch_snapshot(struct touch_owner_now*out){
 *out=(struct touch_owner_now){
  .request=ld(&bootstrap.ingress.owner.request),.phase=ld(&phase),
  .ready=ld(&ready),.stop=ld(&stop),.error=ld(&error),
  .final_requested=ld(&final_requested),.ingress_error=ld(&bootstrap.ingress.error),
  .prepared=ld(&bootstrap.ingress.prepared),.owner_error=ld(&bootstrap.ingress.owner.error),
  .bootstrap_error=ld(&bootstrap.error),.bootstrap_ready=ld(&bootstrap.ready),
  .bootstrap_state=ld(&bootstrap.ingress.owner.bootstrap_state),
  .act_claim=ld(&bootstrap.ingress.owner.act_claim),.ui_tid=ld(&bundle.s.ui_tid)};
}
static int touch_owner_activation(void*x,uint32_t*ui,uint32_t*request){
 (void)x;if(!ui||!request)return 0;*ui=0;*request=0;
 if(!worker_tid||tid(0)!=worker_tid)return 0;
 struct touch_owner_now before,after;struct lo_status current;
 touch_snapshot(&before);
 if(before.prepared!=1||before.ready!=1||before.phase!=22||
    before.stop||before.error||before.final_requested)return 0;
 if(lo_report(&bootstrap.ingress.owner,&current)!=LO_OK)return 0;
 touch_snapshot(&after);
 if(!touch_owner_gate(&before,&after,&current))return 0;
 *ui=before.ui_tid;*request=before.request;return 1;
}
static int touch_owner_eligible(void*x,uint32_t*ui){uint32_t request;return touch_owner_activation(x,ui,&request);}
static void touch_loader_step(void){
 uint32_t now=now_ms();if(!now||(touch_loader_last_ms&&now-touch_loader_last_ms<20u))return;
 touch_loader_last_ms=now;
 if(!touch_loader_report.abi)tl_init(&touch_loader_report);
 struct tl_port ports=tln_ports(&touch_loader_context);
 /* Optional failures are diagnostics only: no failure(), provider call or ACK.
  * One call site after native tick+publish; monotonic20ms throttle also covers
  * an interrupted original nanosleep without adding a timer or worker. */
 (void)tl_step(&touch_loader_report,&ports);
}
static void publish_cache(void){uint32_t out[2048]={0};out[0]=1;out[1]=sizeof out;out[2]=OWNER_BUILD;out[3]=ld(&phase);out[4]=ld(&error);out[5]=pid;out[6]=worker_tid;out[7]=ld(&created);out[8]=ready;out[9]=descriptor;out[10]=self_pin!=0;out[11]=db_pin!=0;out[12]=sem_calls;out[13]=ld(&exited);out[14]=ld(&stop);out[15]=1;
 if(ld(&bootstrap.ingress.prepared)){lo_report(&bootstrap.ingress.owner,&lifecycle);copy(out+16,&lifecycle,sizeof lifecycle);}
 _Static_assert(sizeof lifecycle<=176*4,"lifecycle section");
 copy(out+192,&platform.s,sizeof platform.s);copy(out+224,&sem_port.status,sizeof sem_port.status);copy(out+256,&lease.status,sizeof lease.status);copy(out+288,&channel.status,sizeof channel.status);
 copy(out+304,&ready_status,sizeof ready_status);copy(out+308,&failure_status,sizeof failure_status);out[312]=ld(&final_requested);out[313]=ld(&final_entered);out[314]=ld(&final_done);out[315]=ld(&bootstrap.accepted);out[316]=ld(&bootstrap.inflight);out[317]=ld(&bootstrap.error);out[318]=ld(&bootstrap.ingress.mailbox);out[319]=ld(&bootstrap.ingress.error);
 copy(out+320,&bundle.s,sizeof bundle.s);copy(out+352,&platform.diagnostic,sizeof platform.diagnostic);copy(out+416,fb_barrier_status(),sizeof(struct fb_barrier_status));
 _Static_assert(sizeof bundle.ap<=320*4,"audio section");_Static_assert(sizeof bundle.mp<=320*4,"menu section");_Static_assert(sizeof bundle.rr<=192*4,"source section");_Static_assert(sizeof bundle.f7<=192*4,"observer section");
 copy(out+512,&bundle.ap,sizeof bundle.ap);copy(out+832,&bundle.mp,sizeof bundle.mp);copy(out+1152,&bundle.rr,sizeof bundle.rr);copy(out+1344,&bundle.f7,sizeof bundle.f7);copy(out+1536,late_report(),sizeof(struct late_status));copy(out+1540,&report_status,sizeof report_status);out[1544]=(uint32_t)failure_probe_rc;copy(out+1552,&bundle.diagnostic,sizeof bundle.diagnostic);out[1558]=bundle.ap.runtime.phase==AP_DISABLED_PINNED;copy(out+1560,&bundle.domain,sizeof bundle.domain);copy(out+1760,bundle.timing,sizeof bundle.timing);
 _Static_assert(1760*4+sizeof bundle.timing<=1952*4,"timing/report sections do not overlap");
 copy(out+1952,&touch_loader_report,sizeof touch_loader_report);
 (void)owner_report_cache_publish(&report_cache,out,sizeof out);
}
static int write_ready(void){return ar_write_ready(READY_DIR,installation,runtime_db_hash,OWNER_BUILD,pid,&ready_status);}
static void *worker(void*x){(void)x;st(&worker_started,1);nap_progress(2);if(qualify())goto done;nap_progress(20);
 for(unsigned i=0;i<1000&&!ld(&stop);i++){int r=rl_acquire(&lease);if(r==RL_OK||r==RL_ALREADY)break;if(r!=RL_BUSY){failure(11);goto done;}pause20();}
 if(!lease.status.owns_reference){failure(12);goto done;}
 nap_progress(21);uint32_t opened=0;
 for(unsigned i=0;i<1000&&!ld(&stop)&&!ld(&error);i++){int r=fb_open(&bundle,&platform);if(!r){opened=1;break;}if(r<0){failure(30);goto done;}publish_cache();pause20();}
 if(!opened){failure(31);goto done;}opened=0;
 for(unsigned i=0;i<1000&&!ld(&stop)&&!ld(&error);i++){int r=late_open(&platform);if(!r){opened=1;break;}if(r<0){failure(52);goto done;}publish_cache();pause20();}
 if(!opened){failure(53);goto done;}if(fb_barrier_init(&platform)){failure(32);goto done;}
 struct lo_config q={.port={&bundle,tid,snapshot,complete,fb_certified_barrier},.audio=bundle.audio_power,.menu=bundle.menu_power,.pid=pid,.im_tid=pid,.worker_tid=worker_tid,.descriptor=descriptor};copy(q.audio_id,bundle.identities[1],16);copy(q.menu_id,bundle.identities[3],16);
 if(bg_prepare(&bootstrap,&q)!=BG_OK){failure(33);goto done;}
 /* Cold INACT is processed through the same fully adopted paused bundle. */
 if(ld(&stop)||ld(&error)){failure(34);goto done;}
 if(fb_start(&bundle,&bootstrap)){failure(35);goto done;}nap_progress(23);publish_cache();
 for(;;){
  if(ld(&error))break;uint32_t now=now_ms();if(!now){failure(36);break;}
  if(ld(&final_requested)){
   if(!ld(&final_entered)){pause20();continue;}
   int r=lo_tick(&bootstrap.ingress.owner,now);if(r==LO_ERROR||r==LO_INVALID){failure(44);break;}
   if(lo_report(&bootstrap.ingress.owner,&lifecycle)!=LO_OK){failure(45);break;}
   if(lifecycle.exit_drained){r=fb_finish(&bundle,&lifecycle);if(r<0){failure(46);break;}if(!r){st(&final_done,1);nap_progress(24);break;}}
  }else{
   int r=bg_tick(&bootstrap,now);if(r==LO_ERROR||r==LO_INVALID){failure(37);break;}
   if(fb_observe(&bundle)<0){failure(38);break;}
   if(ld(&bootstrap.ready)&&!ready){if(write_ready()){failure(39);break;}ready=1;nap_progress(22);}
  }
  publish_cache();
  touch_loader_step();
  if(!disabled_reported&&bundle.ap.runtime.phase==AP_DISABLED_PINNED&&lifecycle.audio.phase==LP_ACTIVE){
   disabled_reported=1;uint32_t report[2048];if(!owner_report_cache_report(&report_cache,report,sizeof report)){
    ar_write_report(READY_DIR,installation,runtime_db_hash,OWNER_BUILD,pid,report,sizeof report,&report_status);
   }publish_cache();
  }
  pause20();
 }
done:if(ld(&error)&&bundle.s.stage==6)failure_probe_rc=fb_observe(&bundle);st(&exited,1);publish_cache();if(ld(&error)){uint32_t report[2048];if(!owner_report_cache_report(&report_cache,report,sizeof report)){ar_write_report(READY_DIR,installation,runtime_db_hash,OWNER_BUILD,pid,report,sizeof report,&report_status);}publish_cache();}return 0;}
EXPORT int A7R_Lifecycle_Init(void){if(__atomic_exchange_n(&claimed,1,__ATOMIC_ACQ_REL))return -1;pid=syscall(20);bg_event(&bootstrap,LO_INIT,tid(0));entry_evidence(1);
 for(unsigned i=0;i<2;i++){void*fn=i?(void*)pthread_join:(void*)pthread_create;const char*name=i?"pthread_join":"pthread_create";const struct pthread_symbol*s=0;for(unsigned j=0;j<2;j++)if(same(ps[j].name,name))s=ps+j;struct info d={0};if(!s||!dladdr(fn,&d)||(!same(d.path,"/lib/libpthread.so.0")&&!same(d.path,"/lib/libpthread-2.11.2.so")&&!same(d.path,"//lib/libpthread.so.0"))||(uint32_t)fn-(uint32_t)d.base!=s->offset||!eq((void*)((uint32_t)fn&~1u),s->anchor,16))return failure(20);}
 self_pin=dlopen("/usr/lib/liba7r_startup_full_v14.so",6);if(!self_pin||dlsym(self_pin,"A7R_Lifecycle_Init")!=(void*)A7R_Lifecycle_Init)return failure(21);if(pthread_create(&thread,0,worker,0))return failure(22);st(&created,1);return 0;
}
static int native_event(uint32_t event){if((unsigned)syscall(20)!=pid)return -1;if(ld(&final_requested))return failure(47);int r=bg_event(&bootstrap,event,tid(0));if(r==LO_ERROR||r==LO_INVALID)failure(48);return r;}
#define ENTRY(name,event) EXPORT int A7R_Lifecycle_##name(void){return native_event(event);}
ENTRY(Exit,LO_EXIT) ENTRY(Sus,LO_SUS) ENTRY(Res,LO_RES) ENTRY(Inact,LO_INACT) ENTRY(Act,LO_ACT)
EXPORT int A7R_Lifecycle_Report(uint32_t*out,unsigned bytes){return owner_report_cache_report(&report_cache,out,bytes);}
EXPORT int A7R_Lifecycle_LiveState(uint32_t*out){
 if(!out)return -1;
 out[0]=ld(&bootstrap.ingress.owner.request);
 out[1]=ld(&bootstrap.ingress.error);
 out[2]=ld(&bootstrap.ingress.prepared);
 out[3]=ld(&bootstrap.ingress.owner.error);
 out[4]=ld(&bootstrap.error);
 out[5]=ld(&bootstrap.ready);
 out[6]=ld(&phase);
 out[7]=ld(&stop);
 out[8]=ld(&error);
 out[9]=ld(&final_requested);
 out[10]=ld(&bootstrap.ingress.owner.bootstrap_state);
 out[11]=ld(&bootstrap.ingress.owner.act_claim);
 return 0;
}
/* Only process finalization on the original serialized IM main thread may
 * request a graceful exit. Foreign exported Exit remains terminal. The worker
 * keeps original providers alive while it obtains a fresh EXIT drain proof,
 * retires audio/source threads, and restores the observer GOT. libosal's fini
 * follows this explicit dependency. Failure never pretends that threads joined;
 * the independent guardian receives an authenticated failure and recovers. */
EXPORT void A7R_Lifecycle_Finalize(void){
 if(__atomic_exchange_n(&finalize_claim,1,__ATOMIC_ACQ_REL))return;
 if((unsigned)syscall(20)!=pid||!ld(&created))return;st(&stop,1);
 if(ld(&bootstrap.begun)){
  if(tid(0)!=pid||ld(&error)||ld(&bootstrap.accepted)!=BG_ALL||!(ld(&bootstrap.ingress.mailbox)&LW_READY)){failure(49);}
  else{st(&final_requested,1);int r=lo_event(&bootstrap.ingress.owner,LO_EXIT);if(r==LO_ERROR||r==LO_INVALID)failure(50);else st(&final_entered,1);}
 }
 if(tid(0)!=worker_tid){void*result=0;pthread_join(thread,&result);}
 /* Do not let dependent finalizers unmap providers under an unretired thread.
  * The boot/runtime guard owns rollback and no-snapshot reboot on this path. */
 if(ld(&bootstrap.begun)&&!ld(&final_done)){failure(51);for(;;)pause20();}
}

__attribute__((destructor))static void finish(void){A7R_Lifecycle_Finalize();}
