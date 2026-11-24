#include "loader.h"
#include "../boot-guard/sha256_local.h"
extern long syscall(long,...);extern void*dlopen(const char*,int),*dlsym(void*,const char*);
struct late_info {const char*name;void*base;const char*symbol;void*address;};extern int dladdr(const void*,struct late_info*);
#ifndef LATE_SPEC_DEFINED
struct late_spec {const char*path;uint32_t bytes,offset;uint8_t hash[32],anchor[16];};
#endif
#include "identities.h"
static void*pins[4];static struct late_status status;
static int eq(const void*a,const void*b,unsigned n){const uint8_t*p=a,*q=b;unsigned v=0;while(n--)v|=*p++^*q++;return !v;}
static int name(const char*a,const char*b){if(!a||!b)return 0;while(*a&&*a==*b){a++;b++;}return *a==*b;}
static int hash(const struct late_spec*s){
 static const uint8_t elf_arm32[7]={0x7f,'E','L','F',1,1,1};
 int f=syscall(5,s->path,0x88000,0);if(f<0)return -1;
 if(!s->bytes){
  uint8_t b[4096],hdr[52]={0};unsigned total=0;int ok=1;
  while(total<=1048576u){
   long n=syscall(3,f,b,sizeof b);if(n<0){ok=0;break;}if(!n)break;
   for(unsigned i=0;i<(unsigned)n&&total+i<52u;i++)hdr[total+i]=b[i];
   total+=(unsigned)n;
  }
  if(syscall(6,f))ok=0;
  unsigned e_type=hdr[16]|((unsigned)hdr[17]<<8),e_machine=hdr[18]|((unsigned)hdr[19]<<8);
  return (ok&&total>=52u&&total<=1048576u&&eq(hdr,elf_arm32,7)&&e_type==3u&&e_machine==40u)?0:-1;
 }
 struct sha256 h;sha_init(&h);uint8_t b[4096],d[32];unsigned left=s->bytes;int ok=1;
 for(unsigned i=0;left&&i<32768;i++){unsigned ask=left>4096?4096:left;long n=syscall(3,f,b,ask);if(n<=0||(unsigned)n>ask){ok=0;break;}left-=n;sha_add(&h,b,n);}if(left||syscall(3,f,b,1))ok=0;sha_end(&h,d);if(syscall(6,f))ok=0;return ok&&eq(d,s->hash,32)?0:-1;
}
static int fail(unsigned e){status.error=e;return -1;}
int late_open(struct np_context*p){
 if(!p||status.error||status.armed||p->s.pid!=(uint32_t)syscall(20)||p->s.worker_tid!=(uint32_t)syscall(224)||np_check(p))return -1;
 /* Original UI/dataflow dependencies must already have been loaded by Sony.
  * Their NOLOAD pins also keep logical original-module dlclose from unloading
  * them before the eventual dependency-ordered process finalization. */
 for(unsigned i=0;i<3;i++){if(pins[i])continue;status.stage=i+1;pins[i]=dlopen(late_specs[i].path,6);if(!pins[i])return 1;status.pins|=1u<<i;if(hash(late_specs+i))return fail(1+i);}
 status.stage=4;if(hash(late_specs+3))return fail(4);pins[3]=dlopen(late_specs[3].path,2);if(!pins[3])return fail(5);status.pins|=8;
 /* dlopen introduced new readable/executable ranges. Validate the retained
  * native context and refresh its map snapshot before checking that code. */
 if(np_check(p))return fail(8);
 int(*arm)(uint32_t)=dlsym(pins[3],"a7r_full_exit_bridge_v14");struct late_info d={0};uint8_t b[16];const struct late_spec*s=late_specs+3;
 if(!arm||!dladdr(arm,&d)||!d.base||(!name(s->path,d.name)&&!(d.name&&d.name[0]=='/'&&name(s->path,d.name+1)))||np_read(p,(uint32_t)arm&~1u,b,16))return fail(6);
 if(s->bytes&&((uint32_t)arm-(uint32_t)d.base!=s->offset||!eq(b,s->anchor,16)))return fail(6);
 if(arm(p->s.pid))return fail(7);status.armed=1;status.stage=5;return 0;
}
const struct late_status*late_report(void){return &status;}
