#if !defined(FB_OFFLINE_ONLY) && !defined(FB_PROTECTED_BOOT_TRIAL)
#error Explicit offline fixture or protected boot trial build is required.
#endif
#include "bundle.h"
#include "../core/sha256_local.h"
extern long syscall(long,...);
extern void *dlopen(const char*,int),*dlsym(void*,const char*);
extern int dlclose(void*);
struct info{const char*path;void*base;const char*symbol;void*address;};extern int dladdr(const void*,struct info*);
struct spec{const char*path,*getter;uint32_t bytes,offset;uint8_t sha[32],anchor[16];};
#include "identities.h"
static void copy(void*a,const void*b,unsigned n){uint8_t*p=a;const uint8_t*q=b;while(n--)*p++=*q++;}
static int eq(const void*a,const void*b,unsigned n){const uint8_t*p=a,*q=b;unsigned d=0;while(n--)d|=*p++^*q++;return !d;}
static int same(const char*a,const char*b){if(!a||!b)return 0;while(*a&&*a==*b){a++;b++;}return *a==*b;}
static int fail(struct fb_context*c,unsigned e,int r){if(!c->s.error)c->s.error=e;c->s.last_rc=r;return -1;}
static int owner(struct fb_context*c){return c&&c->platform&&c->platform->s.pid==(uint32_t)syscall(20)&&c->platform->s.worker_tid==(uint32_t)syscall(224);}
static int hash_file(const struct spec*s){
 static const uint8_t elf_arm32[7]={0x7f,'E','L','F',1,1,1};
 int fd=syscall(5,s->path,0x88000,0);if(fd<0)return -1;
 if(!s->bytes){
  uint8_t b[4096],hdr[52]={0};unsigned total=0;int good=1;
  while(total<=1048576u){
   long r=syscall(3,fd,b,sizeof b);if(r<0){good=0;break;}if(!r)break;
   for(unsigned i=0;i<(unsigned)r&&total+i<52u;i++)hdr[total+i]=b[i];
   total+=(unsigned)r;
  }
  if(syscall(6,fd))good=0;
  unsigned e_type=hdr[16]|((unsigned)hdr[17]<<8),e_machine=hdr[18]|((unsigned)hdr[19]<<8);
  return (good&&total>=52u&&total<=1048576u&&eq(hdr,elf_arm32,7)&&e_type==3u&&e_machine==40u)?0:-1;
 }
 struct sha256 h;sha_init(&h);uint8_t b[4096],d[32];unsigned left=s->bytes;int good=1;
 for(unsigned i=0;left&&i<32768;i++){unsigned want=left>4096?4096:left;long r=syscall(3,fd,b,want);if(r<=0||(unsigned)r>want){good=0;break;}sha_add(&h,b,r);left-=r;}
 if(left||syscall(3,fd,b,1)!=0)good=0;sha_end(&h,d);if(syscall(6,fd))good=0;return good&&eq(d,s->sha,32)?0:-1;
}
static int name_ok(const char*path,const char*observed){return same(path,observed)||(observed&&observed[0]=='/'&&same(path,observed+1));}
static void* symbol(struct fb_context*c,unsigned index,const char*name){
 const struct spec*s=specs+index;void*p=dlsym(c->pins[index],name);struct info d={0};uint8_t b[16];
 if(!p||!dladdr(p,&d)||!d.base||!name_ok(s->path,d.path)||(c->bases[index]&&c->bases[index]!=(uint32_t)d.base))return 0;
 if(s->bytes&&s->offset&&same(name,s->getter)&&((uint32_t)p-(uint32_t)d.base!=s->offset||np_read(c->platform,(uint32_t)p&~1u,b,16)||!eq(b,s->anchor,16)))return 0;
 c->bases[index]=(uint32_t)d.base;return p;
}
static int api_memory(struct fb_context*c,unsigned index,const void*ptr,unsigned bytes,unsigned first_function){
 uint32_t words[16];if(bytes>sizeof words||np_read(c->platform,(uint32_t)ptr,words,bytes))return -1;
 for(unsigned i=first_function;i<bytes/4;i++){struct info d={0};if(!words[i]||!dladdr((void*)words[i],&d)||(uint32_t)d.base!=c->bases[index]||!name_ok(specs[index].path,d.path))return -1;}return 0;
}
static int identities(struct fb_context*c){
 int fd=syscall(5,"/dev/urandom",0x88000,0);if(fd<0)return -1;struct np_stat s={0};int good=!syscall(197,fd,&s)&&(s.mode&0170000)==0020000&&s.rdev==0x109;
 long n=good?syscall(3,fd,c->identities,sizeof c->identities):-1;if(syscall(6,fd)||n!=sizeof c->identities)return -1;
 uint8_t z[16]={0};for(unsigned i=0;i<5;i++){if(eq(c->identities[i],z,16))return -1;for(unsigned j=0;j<i;j++)if(eq(c->identities[i],c->identities[j],16))return -1;}return 0;
}
/* Read the current proc task name and starttime twice. This identifies a
 * candidate only; the menu's original timer callback independently checks
 * its actual TID, return PC, timer object and dispatch flag before UI writes. */
extern int fb_ui_candidate(struct np_context*,void*,uint32_t*,uint32_t*,uint32_t*,uint32_t*);
int fb_open(struct fb_context*c,struct np_context*p){
 if(!c||!p||c->s.stage>1||c->s.error)return -1;
 if(!c->s.stage){c->platform=p;c->s.abi=1;c->s.bytes=sizeof c->s;c->s.stage=1;if(!owner(c)||np_check(p)||identities(c))return fail(c,1,0);}
 if(c->platform!=p||!owner(c)||np_check(p))return fail(c,1,0);
 for(unsigned i=0;i<6;i++){if(c->pins[i])continue;c->s.provider=i;
  /* UI creation is later than this module's Init callback. A missing
   * NOLOAD original UI provider is pending, without starting any feature. */
  if(i==5){c->pins[i]=dlopen(specs[i].path,6);if(!c->pins[i])return 1;c->s.pins|=1u<<i;if(hash_file(specs+i))return fail(c,2,i);}
  else{if(hash_file(specs+i))return fail(c,2,i);c->pins[i]=dlopen(specs[i].path,2);if(!c->pins[i])return fail(c,3,i);c->s.pins|=1u<<i;}
 }
 if(np_check(p))return fail(c,4,0);
 const void*(*get)(void)=symbol(c,0,specs[0].getter);if(!get)return fail(c,5,0);c->source=get();
 get=symbol(c,2,specs[2].getter);if(!get)return fail(c,5,2);c->observer=get();
 get=symbol(c,3,specs[3].getter);if(!get)return fail(c,5,3);c->audio=get();
 get=symbol(c,4,specs[4].getter);if(!get)return fail(c,5,4);c->menu=get();
 get=symbol(c,3,"a7r_capture_power_v12");if(!get)return fail(c,6,3);c->audio_power=get();
 c->audio_diagnostic=symbol(c,3,"a7r_capture_diagnostics_v12");if(!c->audio_diagnostic)return fail(c,6,3);
 c->audio_domain=symbol(c,3,"a7r_capture_domain_v12");if(!c->audio_domain)return fail(c,6,3);
 c->audio_timing=symbol(c,3,"a7r_capture_timing_v12");if(!c->audio_timing)return fail(c,6,3);
 c->audio_certify=symbol(c,3,"a7r_capture_certify_v12");if(!c->audio_certify)return fail(c,6,3);
 get=symbol(c,4,"a7r_menu_power_v21");if(!get)return fail(c,6,4);c->menu_power=get();
 if(api_memory(c,0,c->source,sizeof *c->source,3)||api_memory(c,2,c->observer,sizeof *c->observer,3)||api_memory(c,3,c->audio,sizeof *c->audio,3)||api_memory(c,4,c->menu,sizeof *c->menu,3)||api_memory(c,3,c->audio_power,sizeof *c->audio_power,3)||api_memory(c,4,c->menu_power,sizeof *c->menu_power,3))return fail(c,7,0);
 if(c->source->abi!=1||c->source->bytes!=sizeof *c->source||c->source->build!=RR_BUILD||c->observer->abi!=1||c->observer->size!=sizeof *c->observer||c->observer->build!=F7_BUILD||c->audio->abi!=1||c->audio->bytes!=sizeof *c->audio||c->audio->build!=AP_BUILD||c->menu->version!=1||c->menu->bytes!=sizeof *c->menu||c->menu->build!=MP_BUILD||c->audio_power->build!=AP_BUILD||c->menu_power->build!=MP_BUILD)return fail(c,8,0);
 int ui=fb_ui_candidate(p,c->pins[5],&c->s.ui_tid,&c->s.ui_start,&c->s.ui_base,&c->s.ui_manager);if(ui>0)return 1;if(ui)return fail(c,9,0);
 c->s.stage=2;return 0;
}
static int adopted(struct fb_context*c,struct bg_control*b,unsigned bit,unsigned owned,int rc,int wanted){
 c->s.last_rc=rc;if(owned){c->s.accepted|=bit;if(bg_adopt(b,bit)!=BG_OK)return fail(c,20+bit,rc);}
 if(!owned||rc!=wanted){bg_fail(b,20+bit);return fail(c,20+bit,rc);}return 0;
}
int fb_start(struct fb_context*c,struct bg_control*b){
 if(!owner(c)||c->s.stage!=2||c->s.error||bg_begin(b)!=BG_OK)return -1;
 /* The caller holds the bundle's loader pins for process lifetime. Every
  * START gets one additional independent reference to transfer explicitly. */
 uint32_t owned=0;int rc;void*ref;
 struct rr_request sr={.op=RR_START};copy(sr.instance,c->identities[0],16);
 if(bg_enter(b,BG_SOURCE)!=BG_OK)return fail(c,30,0);ref=dlopen(specs[0].path,6);if(!ref)return fail(c,30,0);rc=c->source->start(ref,&sr,&owned,&c->rr);if(adopted(c,b,BG_SOURCE,owned,rc,RR_OK))return -1;c->s.stage=3;
 if(c->rr.runtime.state!=RR_RUNNING||c->rr.runtime.stage!=7||c->rr.runtime.error||c->rr.core.control!=4||c->rr.core.snapshot_generation)return fail(c,31,0);
 owned=0;if(bg_enter(b,BG_OBSERVER)!=BG_OK)return fail(c,32,0);ref=dlopen(specs[2].path,6);if(!ref)return fail(c,32,0);rc=c->observer->attach(ref,c->identities[2],&owned,&c->f7);if(adopted(c,b,BG_OBSERVER,owned,rc,F7_OK))return -1;c->s.stage=4;
 if(c->f7.phase!=F7_ARMED||c->f7.generation!=1||!c->f7.owns_reference||c->f7.pid!=c->platform->s.pid)return fail(c,33,0);
 struct ap_request ar={.op=AP_START,.control=1,.asset=2,.epoch=1,.source_control=4};copy(ar.instance,c->identities[1],16);copy(ar.source_instance,c->identities[0],16);copy(ar.source_nonce,c->identities[4],16);copy(ar.reserved,c->identities[2],16);ar.reserved[4]=1;ar.reserved[5]=1;
 owned=0;if(bg_enter(b,BG_AUDIO)!=BG_OK)return fail(c,34,0);ref=dlopen(specs[3].path,6);if(!ref)return fail(c,34,0);rc=c->audio->start(ref,&ar,&owned,&c->ap);if(adopted(c,b,BG_AUDIO,owned,rc,AP_PENDING))return -1;c->s.stage=5;
 struct mp_bind mr={.version=1,.bytes=48,.owner_tid=c->s.ui_tid,.backend_kind=2};copy(mr.audio_instance,c->identities[1],16);copy(mr.activation_nonce,c->identities[3],16);
 owned=0;if(bg_enter(b,BG_MENU)!=BG_OK)return fail(c,35,0);ref=dlopen(specs[4].path,6);if(!ref)return fail(c,35,0);rc=c->menu->start(ref,&mr,&owned,&c->mp);if(adopted(c,b,BG_MENU,owned,rc,0))return -1;c->s.stage=6;return 0;
}
int fb_observe(struct fb_context*c){
 if(!owner(c)||c->s.stage!=6||c->s.error)return -1;struct ap_request q={.op=AP_QUERY};copy(q.instance,c->identities[1],16);int r=c->audio->dispatch(&q,&c->ap);if(r==AP_BUSY)return 1;int disabled=c->ap.runtime.phase==AP_DISABLED_PINNED&&c->ap.runtime.error==(uint32_t)-9464&&c->ap.runtime.stage==9&&!c->ap.runtime.thread_exited&&!c->ap.runtime.ref_uncertain&&!c->ap.runtime.automatic_admission&&c->ap.resources.gate&&c->ap.owner.phase==A7R_IDLE&&!c->ap.owner.held_message;
 if(c->audio_diagnostic){struct fr_diagnostic d={0};int dr=c->audio_diagnostic(&d);if(!dr&&d.abi==1&&d.bytes==sizeof d)copy(&c->diagnostic,&d,sizeof d);}
 if(c->audio_timing){uint32_t d[8]={0};if(!c->audio_timing(d)&&d[0]==1&&d[1]==32)copy(c->timing,d,sizeof d);}
 if(c->audio_domain){struct fr_domain_record d={0};int dr=c->audio_domain(&d);if(!dr&&d.abi==1&&d.bytes==sizeof d)copy(&c->domain,&d,sizeof d);}
 if(r||(!disabled&&c->ap.runtime.error)||c->ap.runtime.phase==AP_HOLD_PINNED)return fail(c,40,r);r=c->menu->query(&c->mp);if(r==2)return 1;if(r||c->mp.error||c->mp.phase==MP_HOLD_PINNED)return fail(c,41,r);return 0;
}
/* One step per owner turn. A proven coordinator EXIT drain is mandatory.
 * This never grants resumed work to stop a parked component. It preserves
 * all custom DMM allocations and all bundle/self/provider pins. */
int fb_finish(struct fb_context*c,const struct lo_status*proof){
 if(!owner(c)||!proof)return -1;
 if(c->s.finish_error)return -1;if(c->s.finish_stage==4)return 0;
 if(!c->s.finish_stage){
  if(c->s.accepted!=BG_ALL||proof->abi!=1||proof->bytes!=sizeof *proof||proof->build!=LO_BUILD||proof->event!=LO_EXIT||proof->error||!proof->exit_drained||!proof->generation||proof->proof_generation!=proof->generation||proof->audio.phase!=LP_PARKED||proof->menu.control.phase!=LP_PARKED||!proof->audio.local_drained||!proof->menu.callback_returned||!proof->menu.route_suspended||proof->menu.view_live||proof->menu.transaction_pending||proof->barrier.stage!=8||proof->barrier.error||!proof->barrier.barrier_ok||!proof->barrier.notify_unchanged||proof->barrier.retained_ids||proof->barrier.held_message){c->s.finish_error=1;return -1;}
  c->s.menu_parked=1;c->s.finish_stage=1;
 }
 if(c->s.finish_stage==1){
  struct ap_request q={.op=AP_STOP};copy(q.instance,c->identities[1],16);int r=c->audio->dispatch(&q,&c->ap);c->s.last_rc=r;
  if(r==AP_BUSY||r==AP_PENDING)return 1;
  if(r||c->ap.runtime.ref_uncertain||!c->ap.runtime.thread_exited||!c->ap.runtime.thread_joined||c->ap.runtime.phase!=AP_DORMANT_PINNED){c->s.finish_error=2;return -1;}
  c->s.audio_stopped=1;c->s.finish_stage=2;
 }
 if(c->s.finish_stage==2){
  int r=c->observer->stop(1,&c->f7);c->s.last_rc=r;if(r==F7_BUSY)return 1;
  if(r||c->f7.phase!=F7_STOPPED_RETAINED||!c->f7.got_restored||!c->f7.owns_reference){c->s.finish_error=3;return -1;}
  /* Restoring the GOT is not proof that old trampoline calls returned.
   * Its code and providers are deliberately retained through process exit. */
  c->s.observer_stopped=1;c->s.finish_stage=3;
 }
 if(c->s.finish_stage==3){
  struct rr_request q={.op=RR_STOP};copy(q.instance,c->identities[0],16);void*transfer=0;uint32_t ticket=0;
  int r=c->source->claim_stop(&q,&transfer,&ticket,&c->rr);c->s.last_rc=r;if(r==RR_PENDING||r==SR_BUSY)return 1;
  if(r||!transfer||!ticket||c->rr.runtime.state!=RR_CLAIMED||!c->rr.runtime.thread_exited||!c->rr.runtime.thread_joined){c->s.finish_error=4;return -1;}
  /* The separate bundle pin is still held. Closing only the explicit
   * transferred runtime-self reference cannot unload this provider. */
  int closed=dlclose(transfer);r=c->source->finish_stop(ticket,!closed,&c->rr);if(closed||r||c->rr.runtime.state!=RR_STOPPED){c->s.finish_error=5;return -1;}
  c->s.source_stopped=1;c->s.finish_stage=4;return 0;
 }
 return 1;
}

extern int fb_barrier_run(void*,struct bp_report*);extern void nb_delay(void);
int fb_certified_barrier(void*context,struct bp_report*r){
 struct fb_context*c=context;
 if(!owner(c)||!c->audio_certify||fb_barrier_run(0,r))return -1;
 for(unsigned i=0;i<20;i++){
  int rc=c->audio_certify(c->identities[1],r);
  if(!rc)return 0;if(rc!=AP_BUSY){r->error=206;return -1;}nb_delay();
 }
 r->error=207;return -1;
}
