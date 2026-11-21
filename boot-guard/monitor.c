#define _GNU_SOURCE
#include "monitor.h"
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
static int read_record(int dir,const char*name,struct gx_record*r){
 int f=openat(dir,name,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(f<0)return errno==ENOENT?0:-1;
 struct stat a,b;unsigned at=0;int ok=!fstat(f,&a)&&S_ISREG(a.st_mode)&&!a.st_uid&&!a.st_gid&&a.st_nlink==1&&(a.st_mode&07777)==0600&&a.st_size==256;
 for(unsigned n=0;ok&&at<256&&n<32;n++){ssize_t rsize=read(f,(char*)r+at,256-at);if(rsize<0&&errno==EINTR)continue;if(rsize<=0){ok=0;break;}at+=(unsigned)rsize;}
 char tail;if(at!=256||read(f,&tail,1)!=0||fstat(f,&b)||a.st_dev!=b.st_dev||a.st_ino!=b.st_ino||a.st_size!=b.st_size||a.st_mode!=b.st_mode||a.st_nlink!=b.st_nlink||a.st_uid!=b.st_uid||a.st_gid!=b.st_gid)ok=0;
 if(close(f))ok=0;return ok?1:-1;
}
int gm_failure_name(char*out,unsigned cap,const char*boot){
 if(!out||!boot||cap<49)return -1;
 for(unsigned i=0;i<36;i++){char v=boot[i];if(i==8||i==13||i==18||i==23){if(v!='-')return -1;}else if(!((v>='0'&&v<='9')||(v>='a'&&v<='f')))return -1;}
 if(boot[36])return -1;memcpy(out,"failure-",8);memcpy(out+8,boot,36);memcpy(out+44,".bin",5);return 0;
}
int gm_arm(struct gm_monitor*m,int dir,const struct gx_config*c){
 if(!m||!c||m->armed||m->error||!c->ready_process)return -1;
 struct gx_record r;uint64_t start=0;int rc=read_record(dir,"ready.bin",&r);if(rc!=1){m->error=1;return -1;}memcpy(&start,r.extra,8);
 if(!gx_valid(&r,c)||r.phase!=GX_READY||r.seq!=1||r.code!=c->ready_build||memcmp(r.boot,c->boot,40)||r.pid<2||!start||!c->ready_process(c->context,r.pid,start)){m->error=2;return -1;}
 m->ready=r;m->armed=1;return 0;
}
int gm_poll(const struct gm_monitor*m,int dir,const struct gx_config*c,uint32_t*error){
 if(!m||!m->armed||m->error||!c||!error)return -1;*error=0;
 char name[49];if(gm_failure_name(name,sizeof name,c->boot))return -1;struct gx_record r;int rc=read_record(dir,name,&r);if(rc!=1)return rc;
 uint32_t e=0;memcpy(&e,r.extra+8,4);
 if(!gx_valid(&r,c)||r.phase!=GX_FAILURE||r.seq!=1||r.code!=c->ready_build||memcmp(r.boot,c->boot,40)||r.pid!=m->ready.pid||memcmp(r.extra,m->ready.extra,8)||!e)return -1;
 *error=e;return 1;
}
