#include "platform.h"
extern void nap_progress(unsigned);
#include "../core/sha256_local.h"
extern void *dlopen(const char*,int),*dlsym(void*,const char*),*dlvsym(void*,const char*,const char*);
extern int dlclose(void*);
struct dl_info{const char*name;void*base;const char*symbol;void*address;};extern int dladdr(const void*,struct dl_info*);
struct np_symbol{const char*name,*version;uint32_t offset;uint8_t anchor[16];};
struct np_spec{const char*path;uint32_t bytes;uint8_t hash[32];const struct np_symbol*symbols;uint32_t count;};
#include "identity.h"
_Static_assert(sizeof(void*)==4,"ARM32 required");
_Static_assert(sizeof(struct np_stat)==104&&offsetof(struct np_stat,mode)==16&&offsetof(struct np_stat,rdev)==32&&offsetof(struct np_stat,size)==48&&offsetof(struct np_stat,blocks)==64&&offsetof(struct np_stat,ino)==96,"ARM stat64 ABI");
static long sc(long n,long a,long b,long c,long d,long e,long f){register long r0 __asm__("r0")=a,r1 __asm__("r1")=b,r2 __asm__("r2")=c,r3 __asm__("r3")=d,r4 __asm__("r4")=e,r5 __asm__("r5")=f,r7 __asm__("r7")=n;__asm__ volatile("svc 0":"+r"(r0):"r"(r1),"r"(r2),"r"(r3),"r"(r4),"r"(r5),"r"(r7):"memory","cc");return r0;}
static long s3(long n,long a,long b,long c){return sc(n,a,b,c,0,0,0);}
static int eq(const void*a,const void*b,uint32_t n){const uint8_t*p=a,*q=b;uint8_t d=0;while(n--)d|=*p++^*q++;return !d;}
static int same(const char*a,const char*b){if(!a||!b)return 0;while(*a&&*a==*b){a++;b++;}return *a==*b;}
static void copy(void*a,const void*b,uint32_t n){uint8_t*p=a;const uint8_t*q=b;while(n--)*p++=*q++;}
static int diagnostic(struct np_context*c,unsigned stage,int error,long rc,uint32_t a,uint32_t n,const char*line){
 struct np_diagnostic*d=&c->diagnostic;d->stage=stage;if(!d->first_stage){d->first_stage=stage;d->reason=error;d->call_rc=rc;d->map_row=c->maps.count;d->addr=a;d->length=n;if(line){unsigned i=0;while(i+1<sizeof d->line&&line[i]){d->line[i]=line[i];i++;}d->line[i]=0;}}return error;
}
static int fail(struct np_context*c,int e){if(!c->s.error)c->s.error=e;c->s.phase=NP_FAILED;return e;}
static int owner(const struct np_context*c){return c&&c->s.pid==(uint32_t)s3(20,0,0,0)&&c->s.worker_tid==(uint32_t)s3(224,0,0,0);}
static int close_one(struct np_context*c,int fd,uint32_t bit){if(s3(6,fd,0,0)){c->s.close_uncertain|=bit;return NP_CLOSE;}return 0;}
static int hash_file(struct np_context*c,const struct np_spec*s){
 long fd=s3(5,(long)s->path,0x80000,0);if(fd<0)return NP_SYSTEM;
 uint8_t b[4096],h[32];uint32_t left=s->bytes,calls=0;struct sha256 sh;sha_init(&sh);int good=1;
 /* Short reads/EINTR consume the finite syscall budget; no unbounded retries. */
 while(left&&calls++<2048){uint32_t ask=left>sizeof b?sizeof b:left;long r=s3(3,fd,(long)b,ask);if(r<=0||(uint32_t)r>ask){good=0;break;}sha_add(&sh,b,r);left-=r;}
 if(left||s3(3,fd,(long)b,1)!=0)good=0;sha_end(&sh,h);int cr=close_one(c,fd,1);if(cr)return cr;return good&&eq(h,s->hash,32)?0:NP_IDENTITY;
}
static int read_mem(struct np_context*c,uint32_t a,void*out,uint32_t n){
 if(!n||n>4096||!out||!np_range(&c->maps,a,n,NP_R))return diagnostic(c,21,NP_MAPS,0,a,n,0);
 c->s.reads++;long r=sc(180,c->s.mem_fd,(long)out,n,0,a,0);return r==(long)n?0:diagnostic(c,22,NP_SYSTEM,r,a,n,0);
}
static int maps_once(struct np_context*c){
 long fd=s3(5,(long)"/proc/self/maps",0x80000,0);if(fd<0)return diagnostic(c,11,NP_SYSTEM,fd,0,0,0);
 c->maps.count=0;c->maps.bytes=0;char chunk[4096],line[NP_MAX_LINE];uint32_t used=0,calls=0;int error=0;
 for(;;){if(++calls>512){error=diagnostic(c,14,NP_MAPS,0,0,calls,0);break;}long n=s3(3,fd,(long)chunk,sizeof chunk);if(n<0||n>(long)sizeof chunk){error=diagnostic(c,12,NP_SYSTEM,n,0,0,0);break;}if(!n){if(used||!c->maps.count){line[used]=0;error=diagnostic(c,13,NP_MAPS,0,0,used,line);}break;}
  c->maps.bytes+=(uint32_t)n;for(long j=0;j<n;j++){char ch=chunk[j];if(ch=='\n'){line[used]=0;if(c->maps.count==NP_MAX_MAPS||!np_parse_map(line,c->maps.rows+c->maps.count)){error=diagnostic(c,15,NP_MAPS,0,0,used,line);break;}if(c->maps.count&&c->maps.rows[c->maps.count-1].hi>c->maps.rows[c->maps.count].lo){error=diagnostic(c,16,NP_MAPS,0,c->maps.rows[c->maps.count-1].hi,c->maps.rows[c->maps.count].lo,line);break;}c->maps.count++;used=0;}else{if(used+1>=sizeof line||ch==0){line[used]=0;error=diagnostic(c,17,NP_MAPS,ch,0,used,line);break;}line[used++]=ch;}}if(error)break;
 }
 int cr=close_one(c,fd,2);c->s.map_count=c->maps.count;c->s.map_bytes=c->maps.bytes;return cr?cr:error;
}
/* /proc maps is streamed across read calls while other startup threads may
 * change VMAs. A backwards/overlapping row cannot authorize a memory read.
 * Discard the entire observation, close its fd, and reopen at most twice.
 * Parsing, I/O and uncertain close errors are never retried. Persistent
 * overlap is still fatal. Identity/pool/fd checks only use a complete scan.
 * No ioctl, pointer dereference or provider call occurs between attempts. */
static int maps(struct np_context*c){
 struct np_diagnostic saved=c->diagnostic;
 for(unsigned attempt=0;attempt<3;attempt++){
  int r=maps_once(c);
  if(!r)return 0;
  if(r!=NP_MAPS||c->diagnostic.first_stage!=16||saved.first_stage||c->s.close_uncertain||attempt==2)return r;
  uint32_t retries=c->diagnostic.reserved[0]+1;
  c->diagnostic=saved;c->diagnostic.reserved[0]=retries;
  c->maps.count=c->maps.bytes=0;
 }
 return NP_MAPS;
}
static int named(const struct np_spec*s,const char*p){if(same(s->path,p))return 1;if(s==&spec_osal)return same(p,"//usr/lib/libosal_uipc.so");return same(p,"/lib/libc.so.6")||same(p,"//lib/libc.so.6");}
static int libraries(struct np_context*c){
 const struct np_spec*specs[]={&spec_osal,&spec_libc};
 for(unsigned k=0;k<2;k++){const struct np_spec*s=specs[k];int r=hash_file(c,s);if(r)return r;c->refs[k]=dlopen(s->path,6);if(!c->refs[k])return NP_LIBRARY;c->s.provider_mask|=1u<<k;
  uint32_t base=0;for(unsigned j=0;j<s->count;j++){const struct np_symbol*t=s->symbols+j;void*p=t->version?dlvsym(c->refs[k],t->name,t->version):dlsym(c->refs[k],t->name);struct dl_info info={0};
   if(!p||!dladdr(p,&info)||!info.base||!named(s,info.name)||(uint32_t)p-(uint32_t)info.base!=t->offset||(base&&base!=(uint32_t)info.base))return NP_LIBRARY;
   base=(uint32_t)info.base;uint8_t actual[16];r=read_mem(c,(uint32_t)p&~1u,actual,sizeof actual);if(r||!eq(actual,t->anchor,sizeof actual))return NP_LIBRARY;
  }if(!base)return NP_LIBRARY;if(k==0){c->s.osal_base=base;c->s.uconf=base+NP_UCONF_OFFSET;}else c->s.libc_base=base;
 }return 0;
}
static int statfd(int fd,struct np_stat*out){return s3(197,fd,(long)out,0)==0;}
static int same_device(const struct np_stat*a,const struct np_stat*b){return a->dev==b->dev&&a->ino==b->ino&&a->rdev==b->rdev&&a->mode==b->mode;}
static int pool(struct np_context*c,const uint32_t*v){
 if(v[0]>0x7fffffffu||!v[1]||v[2]!=0x80000||v[1]>UINT32_MAX-v[2])return diagnostic(c,31,NP_FD,0,v[1],v[2],0);
 struct np_diagnostic*d=&c->diagnostic;if(!d->first_stage){d->expected_lo=v[1];d->expected_hi=v[1]+v[2];d->pool_lo=d->pool_hi=d->pool_offset=d->pool_flags=0;}
 for(unsigned i=0;i<c->maps.count;i++){const struct np_map*m=c->maps.rows+i;if(!d->first_stage&&m->lo<=v[1]&&v[1]<m->hi){d->pool_lo=m->lo;d->pool_hi=m->hi;d->pool_offset=m->offset;d->pool_flags=m->flags;}if(m->lo==v[1]&&m->hi==v[1]+v[2]&&m->kind==NP_UIPC&&!(m->offset&4095u)&&m->offset<=UINT32_MAX-v[2]&&(!c->s.duplicate_acquired||m->offset==c->s.pool_offset)&&m->flags==(NP_R|NP_W|NP_SHARED)&&m->inode==c->device.ino&&m->major==((c->device.dev>>8)&0xfff)&&m->minor==((c->device.dev&0xff)|((c->device.dev>>12)&0xfff00))){c->s.pool_offset=m->offset;return 0;}}return diagnostic(c,32,NP_MAPS,0,v[1],v[2],0);
}
static int check(struct np_context*c);
uint32_t np_size(void){return sizeof(struct np_context);}
int np_open(struct np_context*c){
 if(!c)return NP_STATE;if(!__sync_bool_compare_and_swap(&c->claimed,0,1))return NP_STATE;
 c->s=(struct np_status){.abi=1,.bytes=sizeof(struct np_status),.build=NP_BUILD,.phase=NP_OPENING,.pid=(uint32_t)s3(20,0,0,0),.worker_tid=(uint32_t)s3(224,0,0,0),.duplicate_fd=-1,.mem_fd=-1};
 c->diagnostic=(struct np_diagnostic){.abi=1,.bytes=sizeof(struct np_diagnostic)};
 if(!c->s.pid||!c->s.worker_tid)return fail(c,NP_IDENTITY);
 nap_progress(10);int r=hash_file(c,&spec_im);if(r)return fail(c,r);
 nap_progress(11);long fd=s3(5,(long)"/proc/self/mem",0x80000,0);if(fd<0)return fail(c,NP_SYSTEM);c->s.mem_fd=fd;
 nap_progress(12);r=maps(c);if(r)return fail(c,r);nap_progress(13);r=libraries(c);if(r)return fail(c,r);
 nap_progress(14);r=read_mem(c,c->s.uconf,c->conf,sizeof c->conf);if(r)return fail(c,r);c->s.source_fd=c->conf[0];
 if(!statfd(c->s.source_fd,&c->device)||((c->device.mode&0xf000)!=0x2000)||c->device.rdev!=0xfbcf)return fail(c,NP_FD);
 r=pool(c,c->conf);if(r)return fail(c,r);c->s.pool_lo=c->conf[1];c->s.pool_hi=c->conf[1]+c->conf[2];
 long fl=s3(221,c->s.source_fd,3,0);if(fl<0||(fl&3)!=2)return fail(c,NP_FD);c->s.source_flags=fl;
 /* Atomic CLOEXEC duplicate; never close or change the original descriptor. */
 nap_progress(15);long dup=s3(221,c->s.source_fd,1030,0);if(dup<0)return fail(c,NP_FD);c->s.duplicate_fd=dup;c->s.duplicate_acquired=1;
 struct np_stat d;if(!statfd(dup,&d)||!same_device(&d,&c->device))return fail(c,NP_CHANGED);
 fl=s3(221,dup,3,0);long ce=s3(221,dup,1,0);if(fl<0||(uint32_t)fl!=c->s.source_flags||ce!=1)return fail(c,NP_FD);c->s.duplicate_flags=fl;c->s.duplicate_cloexec=ce;
 c->s.phase=NP_HELD;return check(c);
}
static int check(struct np_context*c){
 if(!c||!owner(c))return NP_THREAD;if(c->s.phase!=NP_HELD)return NP_STATE;c->s.checks++;
 int r=maps(c);if(r)return fail(c,r);uint32_t conf[9];r=read_mem(c,c->s.uconf,conf,sizeof conf);if(r)return fail(c,r);
 /* uconf+0x18 is the proxy-thread array, +0x20 an atomically incremented
  * callback-registration count. Original 1b18 changes these during normal
  * startup, without replacing fd or either mapping. They are not identity.
  * Retain all fd/mapping/size/control-queue identity fields, stat, flags,
  * exact pool range and offset checks. Never adopt a new mapping or fd. */
 uint32_t changed=0;for(unsigned i=0;i<9;i++)if(conf[i]!=c->conf[i])changed|=1u<<i;
 c->s.conf_changed_mask=changed;c->s.conf_identity_changed_mask=changed&0xbfu;
 if(c->s.conf_identity_changed_mask)return fail(c,NP_CHANGED);
 struct np_stat a,b;if(!statfd(c->s.source_fd,&a)||!statfd(c->s.duplicate_fd,&b)||!same_device(&a,&c->device)||!same_device(&b,&c->device))return fail(c,NP_CHANGED);
 long af=s3(221,c->s.source_fd,3,0),bf=s3(221,c->s.duplicate_fd,3,0);if(af<0||bf<0||(uint32_t)af!=c->s.source_flags||(uint32_t)bf!=c->s.duplicate_flags||s3(221,c->s.duplicate_fd,1,0)!=1)return fail(c,NP_CHANGED);
 r=pool(c,conf);if(r)return fail(c,r);return 0;
}
int np_check(struct np_context*c){return check(c);}
int np_check_release(struct np_context*c){
 if(!c)return NP_STATE;c->diagnostic.release_checks++;int e=0;
 if(!owner(c))e=NP_THREAD;
 else if((c->s.phase!=NP_HELD&&c->s.phase!=NP_FAILED)||!c->s.duplicate_acquired||c->s.release_attempted||c->s.close_uncertain||c->s.duplicate_fd<0||c->s.duplicate_fd==(int)c->s.source_fd||c->s.provider_mask!=3||!c->refs[0]||!c->refs[1])e=NP_STATE;
 else{struct np_stat d;long fl=s3(221,c->s.duplicate_fd,3,0),ce=s3(221,c->s.duplicate_fd,1,0);if(!statfd(c->s.duplicate_fd,&d)||!same_device(&d,&c->device)||fl<0||(uint32_t)fl!=c->s.duplicate_flags||ce!=1)e=NP_CHANGED;}
 if(e&&!c->diagnostic.release_error)c->diagnostic.release_error=e;return e;
}
int np_read(struct np_context*c,uint32_t a,void*out,uint32_t n){if(!c||!owner(c))return NP_THREAD;if(c->s.phase!=NP_HELD)return NP_STATE;return read_mem(c,a,out,n);}
int np_report(const struct np_context*c,struct np_status*out){if(!c||!out)return NP_STATE;copy(out,&c->s,sizeof *out);return 0;}
int np_release_preuse(struct np_context*c){
 if(!c||!owner(c))return NP_THREAD;if(c->s.phase==NP_COLD||c->s.phase==NP_RELEASED||c->s.release_attempted)return NP_STATE;c->s.release_attempted=1;
 /* Claimed before close; an interrupted/uncertain close is never replayed. */
 int error=0;if(c->s.duplicate_fd>=0){int fd=c->s.duplicate_fd;c->s.duplicate_fd=-1;if(close_one(c,fd,4))error=NP_CLOSE;}
 if(c->s.mem_fd>=0){int fd=c->s.mem_fd;c->s.mem_fd=-1;if(close_one(c,fd,8))error=NP_CLOSE;}
 for(int i=1;i>=0;i--){void*p=c->refs[i];if(p){c->refs[i]=0;if(dlclose(p)){c->s.close_uncertain|=16u<<i;error=NP_CLOSE;}else c->s.provider_mask&=~(1u<<i);}}
 c->s.phase=error?NP_FAILED:NP_RELEASED;if(error&&!c->s.error)c->s.error=error;return error;
}
