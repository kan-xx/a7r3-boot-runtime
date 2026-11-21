#include "native_loader.h"
#include "../core/ready_record.h"
extern long syscall(long,...);
extern void *dlopen(const char *,int),*dlsym(void *,const char *);
extern int dlclose(void *);
struct tln_info {const char *path;void *base;const char *symbol;void *address;};
extern int dladdr(const void *,struct tln_info *);
#define MANIFEST_PATH "/usr/lib/a7r_touch_boot_v1.bin"
#define CORE_PATH "/usr/lib/liba7r_touch_full_runtime_v7.so"
#define CORE_PATH_DOUBLE "/" CORE_PATH
#define OWNER_PATH "/usr/lib/liba7r_startup_full_v14.so"
/* One existing owner worker only. Borrowed refs/fds are never opened/released
 * by this copy. np_check/np_read may mutate only this private BSS observation,
 * never the accepted owner's platform status/maps/diagnostic. No large stack. */
static struct np_context loader_platform;
static int equal(const void*a,const void*b,unsigned n){const uint8_t*p=a,*q=b;unsigned d=0;for(unsigned i=0;i<n;i++)d|=p[i]^q[i];return !d;}
static int same(const char*a,const char*b){if(!a||!b)return 0;while(*a&&*a==*b){a++;b++;}return *a==*b;}
static struct vf_identity identity(const struct np_stat*s){return(struct vf_identity){s->dev,s->ino,s->size,s->mode,s->nlink,s->uid,s->gid,s->mtime,s->mtimens,s->ctime,s->ctimens};}
static int stat_ok(const struct np_stat*s,unsigned mode,uint32_t bytes){return s->dev==0xfc0fu&&s->mode==(0x8000u|mode)&&!s->uid&&!s->gid&&s->nlink==1&&s->size==bytes;}
static int open_file(void*x,const char*path){(void)x;return(int)syscall(5,path,AR_CLOEXEC|AR_NOFOLLOW,0);}
static int stat_file(void*x,int fd,struct vf_identity*out){(void)x;struct np_stat s={0};if(syscall(197,fd,&s))return -1;*out=identity(&s);return 0;}
static int read_file(void*x,int fd,void*out,uint32_t n){(void)x;return(int)syscall(3,fd,out,n);}
static int close_file(void*x,int fd){(void)x;return(int)syscall(6,fd);}
static struct vf_ports file_ports(void){return(struct vf_ports){0,open_file,stat_file,read_file,close_file};}
static int close_once(struct tln_context*c,int*fd){int owned=*fd;*fd=-1;if(owned>=0&&syscall(6,owned)){c->close_uncertain=1;return 0;}return !c->close_uncertain;}
static int read_exact(int fd,void*out,unsigned bytes){unsigned at=0;for(unsigned i=0;at<bytes&&i<128;i++){long n=syscall(3,fd,(uint8_t*)out+at,bytes-at);if(n<=0||(unsigned)n>bytes-at)return 0;at+=(unsigned)n;}char extra;return at==bytes&&syscall(3,fd,&extra,1)==0;}
static int cancel_verification(void*x){
 struct tln_context*c=x;if(!c)return 0;
 c->verify_failed=1;c->artifact_verified=0;
 if(c->verifier.abi){struct vf_ports p=file_ports();if(vf_cancel(&c->verifier,&p)!=VF_DONE||c->verifier.fd>=0||c->verifier.close_uncertain)c->close_uncertain=1;}
 return !c->close_uncertain;
}
static int verification_failure(struct tln_context*c){(void)cancel_verification(c);return TL_VERIFY_FAILED_RESULT;}
static int private_result(struct tln_context*c,int rc){
 c->platform_error=(uint32_t)rc;
 c->platform_close_uncertain|=loader_platform.s.close_uncertain;
 if(c->platform_close_uncertain){c->close_uncertain=1;(void)cancel_verification(c);return -1;}
 return rc;
}
static int private_check(struct tln_context*c){
 loader_platform=*c->platform;c->platform_checks++;
 return private_result(c,np_check(&loader_platform));
}
static int private_read(struct tln_context*c,uint32_t address,void*out,uint32_t n){return private_result(c,np_read(&loader_platform,address,out,n));}
static int manifest_read(struct tln_context*c){
 int fd=open_file(0,MANIFEST_PATH);if(fd<0)return 0;
 struct np_stat first={0},last={0};struct touch_boot_manifest next;
 int good=!syscall(197,fd,&first)&&stat_ok(&first,0444,128)&&read_exact(fd,&next,128)&&!syscall(197,fd,&last);
 struct vf_identity a=identity(&first),b=identity(&last);
 if(!good||!vf_identity_equal(&a,&b))good=0;
 if(!close_once(c,&fd))good=0;
 if(!good||!tbm_validate(&next))return 0;
 if(c->manifest_verified)return equal(&next,&c->manifest,128)&&vf_identity_equal(&a,&c->manifest_identity);
 c->manifest=next;c->manifest_identity=a;c->manifest_verified=1;return 1;
}
static int begin_verification(struct tln_context*c){
 int fd=open_file(0,OWNER_PATH);if(fd<0)return 0;
 struct np_stat first={0};int good=!syscall(197,fd,&first)&&first.size>=16384&&first.size<=1048576&&stat_ok(&first,0555,(uint32_t)first.size);
 if(!close_once(c,&fd))good=0;if(!good)return 0;
 c->owner_identity=identity(&first);
 c->config[0]=(struct vf_config){.path=CORE_PATH,.bytes=c->manifest.core_bytes,.mode=0555,.flags=VF_ROOT_ONLY};
 c->config[1]=(struct vf_config){.path=OWNER_PATH,.bytes=(uint32_t)first.size,.mode=0555,.flags=VF_ROOT_ONLY};
 for(unsigned i=0;i<32;i++){c->config[0].sha256[i]=c->manifest.core_sha256[i];c->config[1].sha256[i]=c->manifest.owner_sha256[i];}
 return vf_init(&c->verifier)==VF_MORE;
}
static int eligible(void*x,uint32_t*ui){struct tln_context*c=x;return c&&c->platform&&c->eligible&&!c->verify_failed&&!c->close_uncertain&&c->eligible(c->owner_context,ui)&&!private_check(c);}
static int activation(void*x,uint32_t*ui,uint32_t*request){struct tln_context*c=x;return c&&c->activation&&!c->verify_failed&&!c->close_uncertain&&c->activation(c->owner_context,ui,request);}
static int resolve_revoked(void*x){struct tln_context*c=x;return c&&c->resolve_owner_revoked==1;}
static int verify(void*x){
 struct tln_context*c=x;if(!c||c->verify_failed||c->close_uncertain)return TL_VERIFY_FAILED_RESULT;
 /* At most128 full-hash steps even if a non-policy caller invokes this port. */
 if(!c->artifact_verified&&c->verify_steps>=TL_MAX_VERIFY_STEPS)return verification_failure(c);
 if(!manifest_read(c))return verification_failure(c);
 struct vf_ports p=file_ports();
 if(c->artifact_verified)return vf_revalidate(&c->verifier,c->config,&p)==VF_DONE?TL_VERIFY_DONE:verification_failure(c);
 if(!c->verifier.abi&&!begin_verification(c))return verification_failure(c);
 c->verify_steps++;int result=vf_step(&c->verifier,c->config,&p);
 if(result==VF_FAILED)return verification_failure(c);
 if(result==VF_MORE)return TL_VERIFY_MORE;
 if(!vf_identity_equal(c->verifier.snapshot+1,&c->owner_identity)||vf_revalidate(&c->verifier,c->config,&p)!=VF_DONE)return verification_failure(c);
 c->artifact_verified=1;return TL_VERIFY_DONE;
}
static void*load(void*x){struct tln_context*c=x;return c->artifact_verified&&!c->verify_failed&&!c->close_uncertain?dlopen(CORE_PATH,2):0;}
static tl_entry resolve(void*x,void*h){
 struct tln_context*c=x;struct tln_info d={0};uint8_t bytes[16];uint32_t ui=0;
 if(!c)return 0;c->resolve_owner_revoked=0;
 if(!c->platform||!c->eligible||c->verify_failed||c->close_uncertain)return 0;
 if(!c->eligible(c->owner_context,&ui)||!ui){c->resolve_owner_revoked=1;return 0;}
 void*p=dlsym(h,"A7R_Touch_Autostart");
 if(!p||!dladdr(p,&d)||!d.base||(!same(d.path,CORE_PATH)&&!same(d.path,CORE_PATH_DOUBLE))||(uintptr_t)p-(uintptr_t)d.base!=c->manifest.entry_offset||private_check(c)||private_read(c,(uint32_t)(uintptr_t)p&~1u,bytes,16)||!equal(bytes,c->manifest.entry_anchor,16))return 0;
 return(tl_entry)p;
}
static int close_owned(void*x,void*h){(void)x;return dlclose(h);}
struct tl_port tln_ports(struct tln_context*c){return(struct tl_port){c,eligible,verify,load,resolve,close_owned,cancel_verification,activation,resolve_revoked};}
