/* Host ASan/UBSan test for fixed-inode /usr space cleanup engine (zero blobs). */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#define CL_CUSTOM_SPECS 1
#define CL_COUNT 4u
#define CL_ALL_MASK ((1u<<CL_COUNT)-1u)
struct cl_spec {const char*name;uint32_t bytes,mode;char sha[65];};
static struct cl_spec cl_specs[CL_COUNT]={
 {"obsolete_a.copy",64u,0555u,{0}},
 {"obsolete_a.retained",64u,0555u,{0}},
 {"obsolete_b.copy",128u,0444u,{0}},
 {"obsolete_b.retained",128u,0444u,{0}},
};
static const char*const cl_names[CL_COUNT]={
 "obsolete_a.copy","obsolete_a.retained","obsolete_b.copy","obsolete_b.retained"
};

#include "../publishers/cleanup/cleanup_engine.c"
#include "../boot-guard/sha256_local.h"

#if defined(__APPLE__)
#define st_mtim st_mtimespec
#define st_ctim st_ctimespec
#endif

struct fixture {int dir,ro,qual_calls,fail_qual,ns_calls,fail_ns,refs,rw_fail,ro_fail,sync_fail,unlink_fail,close_fail,fake_ino;unsigned rw,rr,unlinks,closes;dev_t realdev;};
static unsigned cases,checks,failed;
static unsigned char payloads[CL_COUNT][128];
#define C(x) do{checks++;if(!(x)){failed++;printf("FAIL cleanup line%u %s\n",__LINE__,#x);}}while(0)

static void init_synthetic_payloads(void){
 for(unsigned i=0;i<CL_COUNT;i++){
  for(unsigned k=0;k<cl_specs[i].bytes;k++)payloads[i][k]=(unsigned char)((i*37u+k)^0x5au);
  struct sha256 h;uint8_t d[32];sha_init(&h);sha_add(&h,payloads[i],cl_specs[i].bytes);sha_end(&h,d);
  for(unsigned k=0;k<32;k++)snprintf(cl_specs[i].sha+2*k,3,"%02x",d[k]);
 }
}
static int fi(void*x,int fd,struct cl_identity*out){struct fixture*f=x;struct stat s;uint8_t b[4096];struct sha256 h;if(fstat(fd,&s)||lseek(fd,0,SEEK_SET))return -1;sha_init(&h);ssize_t n;while((n=read(fd,b,sizeof b))>0)sha_add(&h,b,n);if(n<0)return -1;memset(out,0,sizeof*out);out->dev=0xfc0f;out->ino=f->fake_ino?99:s.st_ino;out->size=s.st_size;out->mode=s.st_mode;out->nlink=s.st_nlink;out->mtime=s.st_mtim.tv_sec;out->mtime_ns=s.st_mtim.tv_nsec;out->ctime=s.st_ctim.tv_sec;out->ctime_ns=s.st_ctim.tv_nsec;sha_end(&h,out->sha);f->realdev=s.st_dev;return 0;}
static int fr(void*x){return ((struct fixture*)x)->ro;}
static int fq(void*x){struct fixture*f=x;return ++f->qual_calls!=f->fail_qual;}
static int fnroot(void*x){(void)x;return 1;}
static int fm(void*x,int roflag){struct fixture*f=x;if(roflag){f->rr++;if(f->ro_fail)return -1;f->ro=1;return 0;}f->rw++;f->ro=0;return f->rw_fail?-1:0;}
static int fo(void*x,unsigned i){struct fixture*f=x;return openat(f->dir,cl_names[i],O_RDONLY|O_NOFOLLOW);}
static int fn(void*x,unsigned i,int fd,const struct cl_identity*id){struct fixture*f=x;struct cl_identity a,b;if(++f->ns_calls==f->fail_ns)return 0;int n=fo(x,i);int ok=n>=0&&!fi(x,fd,&a)&&!fi(x,n,&b)&&cl_same(&a,id)&&cl_same(&b,id);if(n>=0)close(n);return ok;}
static int rf(void*x,const struct cl_identity ids[CL_COUNT],const int held[CL_COUNT]){(void)ids;(void)held;return ((struct fixture*)x)->refs;}
static int fu(void*x,unsigned i){struct fixture*f=x;f->unlinks++;if(f->unlink_fail==(int)i+1)return -1;return unlinkat(f->dir,cl_names[i],0);}
static int fa(void*x,unsigned i){struct fixture*f=x;struct stat s;return fstatat(f->dir,cl_names[i],&s,AT_SYMLINK_NOFOLLOW)<0;}
static int fs(void*x){struct fixture*f=x;return f->sync_fail?-1:fsync(f->dir);}
static int fc(void*x,int fd){struct fixture*f=x;f->closes++;int r=close(fd);return f->close_fail?-1:r;}
static struct cl_api api(struct fixture*f){return(struct cl_api){f,fr,fq,fnroot,fm,fo,fi,fn,rf,fu,fa,fs,fc};}
static struct fixture fresh(char*tpl_out){
 strcpy(tpl_out,"/tmp/a7r-clfix-XXXXXX");char*p=mkdtemp(tpl_out);C(p!=0);
 struct fixture f={.dir=open(p,O_RDONLY|O_DIRECTORY),.ro=1};C(f.dir>=0);
 for(unsigned i=0;i<CL_COUNT;i++){
  int b=openat(f.dir,cl_names[i],O_WRONLY|O_CREAT|O_EXCL,cl_specs[i].mode);C(b>=0);
  C(write(b,payloads[i],cl_specs[i].bytes)==(ssize_t)cl_specs[i].bytes);close(b);
 }
 cases++;return f;
}
static void finish(struct fixture*f,const char*path){
 for(unsigned i=0;i<CL_COUNT;i++)unlinkat(f->dir,cl_names[i],0);
 unlinkat(f->dir,"extra",0);close(f->dir);rmdir(path);
}
int main(void){
 init_synthetic_payloads();
 char tpl[64];struct cl_result r;
 struct fixture f=fresh(tpl);struct cl_api a=api(&f);C(cl_run(&a,0,&r)==0&&r.verified&&!r.deleted&&r.readonly&&!f.rw&&!f.rr);C(!fa(&f,0)&&!fa(&f,1));finish(&f,tpl);
 f=fresh(tpl);a=api(&f);C(!cl_run(&a,1,&r)&&r.deleted==CL_ALL_MASK&&r.readonly&&f.rw==1&&f.rr==1);C(fa(&f,0)&&fa(&f,1));finish(&f,tpl);
 f=fresh(tpl);a=api(&f);f.fail_qual=1;C(cl_run(&a,1,&r)==CL_QUALIFY&&!f.rw&&!r.deleted);finish(&f,tpl);
 f=fresh(tpl);a=api(&f);f.ro=0;C(cl_run(&a,1,&r)==CL_INVALID&&!f.rw&&!r.deleted);finish(&f,tpl);
 f=fresh(tpl);a=api(&f);C(!fchmodat(f.dir,cl_names[0],0644,0));int fd=openat(f.dir,cl_names[0],O_WRONLY);char z=0;C(fd>=0&&pwrite(fd,&z,1,0)==1);close(fd);C(!fchmodat(f.dir,cl_names[0],0555,0));C(cl_run(&a,1,&r)==CL_CANDIDATE&&!f.rw&&!r.deleted);finish(&f,tpl);
 f=fresh(tpl);a=api(&f);C(!linkat(f.dir,cl_names[0],f.dir,"extra",0));C(cl_run(&a,1,&r)==CL_CANDIDATE&&!f.rw);finish(&f,tpl);
 f=fresh(tpl);a=api(&f);f.fake_ino=1;C(cl_run(&a,1,&r)==CL_DISTINCT&&!f.rw);finish(&f,tpl);
 f=fresh(tpl);a=api(&f);f.fail_ns=CL_COUNT*2+1;C(cl_run(&a,1,&r)==CL_CHANGED&&r.readonly&&f.rr==1&&!r.deleted);finish(&f,tpl);
 f=fresh(tpl);a=api(&f);f.rw_fail=1;C(cl_run(&a,1,&r)==CL_MOUNT&&r.readonly&&f.rr==1&&!r.deleted);finish(&f,tpl);
 f=fresh(tpl);a=api(&f);f.unlink_fail=2;C(cl_run(&a,1,&r)==CL_UNLINK&&r.deleted==1&&r.readonly&&f.rr==1);unsigned prior_rw=f.rw,prior_unlinks=f.unlinks;C(cl_run(&a,1,&r)==CL_CANDIDATE&&f.rw==prior_rw&&f.unlinks==prior_unlinks);finish(&f,tpl);
 f=fresh(tpl);a=api(&f);f.sync_fail=1;C(cl_run(&a,1,&r)==CL_SYNC&&r.deleted==1&&r.readonly&&f.rr==1);finish(&f,tpl);
 f=fresh(tpl);a=api(&f);f.fail_qual=4;C(cl_run(&a,1,&r)==CL_QUALIFY&&r.deleted==1&&r.readonly&&f.rr==1);finish(&f,tpl);
 f=fresh(tpl);a=api(&f);f.ro_fail=1;C(cl_run(&a,1,&r)==CL_READONLY&&r.deleted==CL_ALL_MASK&&!r.readonly&&f.rr==1);finish(&f,tpl);
 f=fresh(tpl);a=api(&f);f.close_fail=1;C(cl_run(&a,1,&r)==CL_CLOSE&&r.deleted==1&&r.readonly&&f.closes==CL_COUNT);finish(&f,tpl);
 f=fresh(tpl);a=api(&f);f.refs=1;C(cl_run(&a,1,&r)==CL_REFERENCED&&!f.rw);finish(&f,tpl);
 printf("OBSOLETE_CLEAN_FIXTURE cases=%u checks=%u failures=%u own_temp_only=1\n",cases,checks,failed);return failed?1:0;
}
