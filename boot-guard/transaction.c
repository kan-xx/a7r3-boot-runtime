#define _GNU_SOURCE
#include "transaction.h"
#include "sha256_local.h"
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
struct identity {struct stat s;unsigned char hash[32];};
static int exact_write(int f,const void *data,size_t size) {
 const unsigned char*p=data;unsigned calls=0;
 while(size&&calls++<1024){ssize_t n=write(f,p,size);if(n<0&&errno==EINTR)continue;if(n<=0)return -1;p+=n;size-=n;}return size?-1:0;
}
static int exact_read(int f,void*data,size_t size) {
 unsigned char*p=data;size_t at=0;unsigned calls=0;
 while(at<size&&calls++<1024){ssize_t n=read(f,p+at,size-at);if(n<0&&errno==EINTR)continue;if(n<=0)return -1;at+=n;}
 unsigned char tail;return at==size&&read(f,&tail,1)==0?0:-1;
}
static int identify(int f,struct identity *x) {
 struct stat after;if(fstat(f,&x->s)||!S_ISREG(x->s.st_mode)||(x->s.st_nlink<1||x->s.st_nlink>2)||x->s.st_size<=0||x->s.st_size>4*1024*1024||lseek(f,0,SEEK_SET))return -1;
 struct sha256 h;sha_init(&h);unsigned char b[4096];off_t left=x->s.st_size;unsigned calls=0;
 while(left&&calls++<2048){size_t n=left>4096?4096:(size_t)left;ssize_t got=read(f,b,n);if(got<0&&errno==EINTR)continue;if(got<=0)return -1;sha_add(&h,b,got);left-=got;}
 if(left||read(f,b,1)||fstat(f,&after)||x->s.st_dev!=after.st_dev||x->s.st_ino!=after.st_ino||x->s.st_size!=after.st_size||x->s.st_mode!=after.st_mode||x->s.st_uid!=after.st_uid||x->s.st_gid!=after.st_gid||after.st_nlink!=x->s.st_nlink)return -1;
 sha_end(&h,x->hash);return 0;
}
static int matches(const struct identity*x,const struct gx_config*c,int original) {
 return x->s.st_size==(off_t)(original?c->original_bytes:c->candidate_bytes)&&x->s.st_mode==(S_IFREG|c->mode)&&x->s.st_uid==c->uid&&x->s.st_gid==c->gid&&x->s.st_nlink>=1&&x->s.st_nlink<=2&&!memcmp(x->hash,original?c->original:c->candidate,32);
}
static int same(const struct identity*a,const struct identity*b) {
 return a->s.st_dev==b->s.st_dev&&a->s.st_ino==b->s.st_ino&&a->s.st_size==b->s.st_size&&a->s.st_mode==b->s.st_mode&&a->s.st_uid==b->s.st_uid&&a->s.st_gid==b->s.st_gid&&a->s.st_nlink==b->s.st_nlink&&!memcmp(a->hash,b->hash,32);
}
static int unchanged(int dir,const char*name,int held,const struct identity*expected) {
 struct identity x;int okay=!identify(held,&x)&&same(&x,expected);int f=openat(dir,name,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
 if(f<0)return 0;if(identify(f,&x)||!same(&x,expected))okay=0;if(close(f))okay=0;return okay;
}
void gx_seal(struct gx_record*r) {struct sha256 h;sha_init(&h);sha_add(&h,(const unsigned char*)r,224);sha_end(&h,r->digest);}
int gx_valid(const struct gx_record*r,const struct gx_config*c) {
 struct gx_record q=*r;gx_seal(&q);
 if(memcmp(r->magic,"A7GXST01",8)||r->abi!=1||r->bytes!=256||!r->seq||r->seq>UINT64_MAX-4||r->phase<GX_STARTED||r->phase>GX_FAILURE||memcmp(r->nonce,c->nonce,16)||memcmp(r->candidate,c->candidate,32)||memcmp(r->digest,q.digest,32)||r->boot[36]||r->boot[37]||r->boot[38]||r->boot[39])return 0;
 for(unsigned i=0;i<36;i++){char v=r->boot[i];if(i==8||i==13||i==18||i==23){if(v!='-')return 0;}else if(!((v>='0'&&v<='9')||(v>='a'&&v<='f')))return 0;}
 for(unsigned i=r->phase==GX_READY?8:r->phase==GX_FAILURE?12:0;i<100;i++)if(r->extra[i])return 0;
 return 1;
}
/* 0 absent, 1 exact record, -1 malformed/uncertain. Two fixed slots keep the
 * other complete phase intact if a write is interrupted. Any damaged slot
 * makes startup recover stock rather than guess that a prior boot succeeded. */
static int read_record(int dir,const char*name,struct gx_record*r) {
 int f=openat(dir,name,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(f<0)return errno==ENOENT?0:-1;
 struct stat s;int okay=!fstat(f,&s)&&S_ISREG(s.st_mode)&&s.st_uid==0&&s.st_gid==0&&s.st_nlink==1&&(s.st_mode&07777)==0600&&s.st_size==256&&!exact_read(f,r,256);
 if(close(f))okay=0;return okay?1:-1;
}
static int publish(int dir,const struct gx_config*c,struct gx_result*out,uint32_t phase,uint32_t code) {
 struct gx_record r={.abi=1,.bytes=256,.seq=out->sequence+1,.phase=phase,.code=code,.pid=getpid()};
 memcpy(r.magic,"A7GXST01",8);memcpy(r.nonce,c->nonce,16);memcpy(r.boot,c->boot,40);memcpy(r.candidate,c->candidate,32);gx_seal(&r);
 const char*name=r.seq&1?"state.a":"state.b";int f=openat(dir,name,O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC,0600);if(f<0)return -1;
 struct stat s;int okay=!fstat(f,&s)&&S_ISREG(s.st_mode)&&!s.st_uid&&!s.st_gid&&s.st_nlink==1&&(s.st_mode&07777)==0600&&s.st_size<=256;
 if(okay&&(ftruncate(f,0)||exact_write(f,&r,256)||fsync(f)))okay=0;
 if(close(f))okay=0;if(okay&&fsync(dir))okay=0;
 struct gx_record back;if(okay&&(read_record(dir,name,&back)!=1||memcmp(&r,&back,256)))okay=0;
 if(okay)out->sequence=r.seq;return okay?0:-1;
}
static int ready(int dir,const struct gx_config*c) {
 struct gx_record r;int v=read_record(dir,"ready.bin",&r);if(v!=1)return v;
 uint64_t start=0;memcpy(&start,r.extra,8);
 return gx_valid(&r,c)&&r.phase==GX_READY&&r.seq==1&&r.code==c->ready_build&&!memcmp(r.boot,c->boot,40)&&r.pid>1&&start&&c->ready_process(c->context,r.pid,start)?1:-1;
}
/* One interrupted startup may be retried in a DIFFERENT kernel generation.
 * Existing files at any relevant failure path, even partial/malformed/symlink,
 * are uncertainty, never permission to retry. No record ABI is added. */
static int failure_absent(int dir,const char boot[40]) {
 char name[49];struct stat st;memcpy(name,"failure-",8);memcpy(name+8,boot,36);
 static const char*const suffix[]={".bin",".new"};
 for(unsigned i=0;i<2;i++){memcpy(name+44,suffix[i],5);if(!fstatat(dir,name,&st,AT_SYMLINK_NOFOLLOW)||errno!=ENOENT)return 0;}
 return 1;
}
static int retry_started(int dir,const struct gx_config*c,const struct gx_record slots[2],const int valid[2],int best) {
 if(!c||c->force_recovery||best<0||best>1||valid[0]!=1||valid[1]!=1||!gx_valid(slots,c)||!gx_valid(slots+1,c))return 0;
 const struct gx_record*latest=slots+best,*previous=slots+(best^1);
 if(latest->phase!=GX_STARTED||previous->phase!=GX_ACCEPTED||latest->code||previous->code||latest->seq!=previous->seq+1||!memcmp(latest->boot,c->boot,40)||!memcmp(previous->boot,latest->boot,40)||!memcmp(previous->boot,c->boot,40))return 0;
 /* Old accepted and interrupted boots are no longer live. Current failure
  * appearance also refuses this optional retry; the original READY wait and
  * post-READY runtime monitor remain unchanged. */
 return failure_absent(dir,previous->boot)&&failure_absent(dir,latest->boot)&&failure_absent(dir,c->boot);
}
static uint64_t now_ms(void) {struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return 0;return (uint64_t)t.tv_sec*1000+t.tv_nsec/1000000;}
static int basename_ok(const char*s) {size_t n=s?strlen(s):0;return n&&n<128&&strcmp(s,".")&&strcmp(s,"..")&&!strchr(s,'/');}
int gx_run(int lib,int journal,const struct gx_config*c,struct gx_result*out) {
 memset(out,0,sizeof *out);out->code=GX_INVALID;int target=-1,source=-1,remount_attempted=0;struct identity a,b;struct stat d;
 if(!c||c->force_recovery>1||!basename_ok(c->target)||!basename_ok(c->standby)||!basename_ok(c->retained)||!strcmp(c->target,c->standby)||!strcmp(c->target,c->retained)||!strcmp(c->standby,c->retained)||!c->remount||!c->readonly||!c->ready_process||c->wait_ms<100||c->wait_ms>120000||!c->original_bytes||!c->candidate_bytes||!memcmp(c->candidate,c->original,32)||c->mode&~0777u||fstat(journal,&d)||!S_ISDIR(d.st_mode)||d.st_uid||d.st_gid||(d.st_mode&07777)!=0700)goto done;
 struct gx_record framing={.abi=1,.bytes=256,.seq=1,.phase=GX_STARTED};memcpy(framing.magic,"A7GXST01",8);memcpy(framing.nonce,c->nonce,16);memcpy(framing.boot,c->boot,40);memcpy(framing.candidate,c->candidate,32);gx_seal(&framing);if(!gx_valid(&framing,c))goto done;
 target=openat(lib,c->target,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);out->code=GX_TARGET;if(target<0||identify(target,&a))goto done;
 if(matches(&a,c,1)){out->code=GX_STOCK;goto done;}if(!matches(&a,c,0))goto done;
 out->code=GX_SOURCE;source=openat(lib,c->standby,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(source<0||identify(source,&b)||!matches(&b,c,1)||b.s.st_nlink!=1||a.s.st_dev!=b.s.st_dev||a.s.st_ino==b.s.st_ino)goto done;
 if(a.s.st_nlink==2&&!unchanged(lib,c->retained,target,&a)){out->code=GX_RETAIN;goto done;}
 struct gx_record slots[2];int v[2]={read_record(journal,"state.a",slots),read_record(journal,"state.b",slots+1)};int best=-1,bad=0;
 for(unsigned i=0;i<2;i++){if(v[i]==1&&!gx_valid(slots+i,c))v[i]=-1;if(v[i]<0)bad=1;if(v[i]==1&&(best<0||slots[i].seq>slots[best].seq))best=i;}
 if(best>=0)out->sequence=slots[best].seq;
 if(v[0]==1&&v[1]==1&&((slots[0].seq>slots[1].seq?slots[0].seq-slots[1].seq:slots[1].seq-slots[0].seq)!=1))bad=1;
 if(bad){out->reason=1;goto restore;}
 if(c->force_recovery){out->reason=6;goto restore;}
 if(best>=0){
  if(slots[best].phase!=GX_ACCEPTED){if(!retry_started(journal,c,slots,v,best)){out->reason=2;goto restore;}}
  else if(!memcmp(slots[best].boot,c->boot,40)){out->ready=1;out->code=GX_CONFIRMED;goto done;}
 }
 /* On the one permitted retry, this normal STARTED overwrites the preceding
  * ACCEPTED. A second interruption therefore leaves STARTED/STARTED and cannot
  * qualify again; only a fresh authenticated READY can publish ACCEPTED. */
 if(publish(journal,c,out,GX_STARTED,0)){out->journal_error=1;out->reason=3;goto restore;}
 uint64_t start=now_ms(),current;if(!start){out->reason=4;goto restore;}
 for(;;){int v=ready(journal,c);if(v==1){if(!unchanged(lib,c->target,target,&a)||!unchanged(lib,c->standby,source,&b)){out->code=GX_CHANGED;goto done;}if(publish(journal,c,out,GX_ACCEPTED,0)){out->journal_error=1;out->reason=3;goto restore;}out->ready=1;out->code=GX_CONFIRMED;goto done;}
  if(v<0)out->invalid_ready++;current=now_ms();if(!current||current<start){out->reason=4;goto restore;}if(current-start>=c->wait_ms){out->reason=5;break;}
  struct timespec p={0,20000000};if(nanosleep(&p,0)){out->reason=4;goto restore;}}
restore:
 if(publish(journal,c,out,GX_RESTORE_INTENT,out->reason))out->journal_error=1;
 out->code=GX_CHANGED;if(!unchanged(lib,c->standby,source,&b)||!unchanged(lib,c->target,target,&a))goto done;
 remount_attempted=1;out->code=GX_MOUNT;if(c->remount(c->context,0)||c->readonly(c->context)!=0)goto done;
 out->code=GX_CHANGED;if(!unchanged(lib,c->standby,source,&b)||!unchanged(lib,c->target,target,&a))goto done;
 /* Standby original is installed and fsynced before the candidate. Recovery
 * only renames this authenticated inode; no partial-copy recovery window. */
 /* Sony kernel fs_may_remount_ro refuses deleted inodes still held by a
  * mapped library. Retain the exact candidate inode before replacing it. */
 out->code=GX_RETAIN;
 if(a.s.st_nlink==1){if(linkat(lib,c->target,lib,c->retained,0))goto done;a.s.st_nlink=2;}
 if(!unchanged(lib,c->target,target,&a)||!unchanged(lib,c->retained,target,&a))goto done;
 out->code=GX_DURABILITY;if(fsync(lib))goto done;
 out->attempted_rename=1;out->code=GX_RENAME;if(renameat(lib,c->standby,lib,c->target))goto done;out->restored=1;
 a.s.st_nlink=1;if(!unchanged(lib,c->retained,target,&a)){out->code=GX_CHANGED;goto done;}
 out->code=GX_DURABILITY;if(fsync(lib))goto done;
 int verify=openat(lib,c->target,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);struct identity restored;int okay=verify>=0&&!identify(verify,&restored)&&same(&restored,&b);if(verify>=0&&close(verify))okay=0;if(!okay)goto done;
 out->code=GX_RESTORED;if(publish(journal,c,out,GX_DONE,0))out->journal_error=1;
done:
 if(remount_attempted&&c->remount(c->context,1))out->code=GX_READONLY;
 if(c&&c->readonly)out->readonly=c->readonly(c->context)==1;
 if(source>=0&&close(source))out->code=GX_DURABILITY;if(target>=0&&close(target))out->code=GX_DURABILITY;
 if(remount_attempted&&!out->readonly)out->code=GX_READONLY;
 return out->code;
}
