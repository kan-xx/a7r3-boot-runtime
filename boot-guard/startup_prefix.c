/* Startup observation ONLY. No firmware target, rollback, mount, signal to
 * another process, device open, im memory access or sound/menu loading. */
#define _GNU_SOURCE
#include "observer.h"
#include "identity.h"
#include "sha256_local.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/file.h>
static const char launcher_hash[]="7b36b457875ec00f5255bdb63374a264d91eb01178951c690a54b18f09a43e14";
static const char shell_hash[]="c8aff800b28c9e61d3a857e146926b3ee9cec1ae93133805479d17f60199970a";
static const char im_hash[]="866729eb0bc1e6f5aba04d8bf8e45491985afe89a078ccb106a1ce2476865225";
static int bounded_read(const char*path,void*out,size_t cap){int fd=open(path,O_RDONLY|O_CLOEXEC);if(fd<0)return-1;size_t at=0;int result=-1;while(at<cap){ssize_t n=read(fd,(char*)out+at,cap-at);if(n<0&&errno==EINTR)continue;if(n<0)goto end;if(!n){result=(int)at;goto end;}at+=n;}char x;ssize_t n;do{n=read(fd,&x,1);}while(n<0&&errno==EINTR);if(!n)result=(int)at;end:if(close(fd))result=-1;return result;}
static int decimal(const char*p,const char*end,uint64_t*out){uint64_t v=0;if(p==end)return 0;for(;p<end;p++){if(*p<'0'||*p>'9'||v>(UINT64_MAX-(unsigned)(*p-'0'))/10)return 0;v=v*10+(unsigned)(*p-'0');}*out=v;return 1;}
static int stat_parse(char*b,int n,uint32_t expect,uint32_t*parent,uint64_t*start){
 if(n<=0||n>1023)return 0;b[n]=0;char*sp=strchr(b,' ');uint64_t pid;if(!sp||!decimal(b,sp,&pid)||pid!=expect||sp[1]!='(')return 0;
 char*last=strrchr(b,')');if(!last||last[1]!=' '||!last[2]||last[3]!=' ')return 0;char*p=last+4;
 for(unsigned field=4;field<=22;field++){char*e=p;while(*e&&*e!=' '&&*e!='\n')e++;if(e==p)return 0;if(field==4||field==22){uint64_t v;if(!decimal(p,e,&v))return 0;if(field==4){if(v>INT32_MAX)return 0;*parent=(uint32_t)v;}else *start=v;}p=e;if(*p==' ')p++;else if(field<22)return 0;}return 1;
}
static int proc_stat(uint32_t pid,uint32_t*parent,uint64_t*start){char name[64],b[1024];int n=snprintf(name,sizeof name,"/proc/%u/stat",pid);if(n<0||(unsigned)n>=sizeof name)return 0;n=bounded_read(name,b,sizeof b-1);return stat_parse(b,n,pid,parent,start);}
static int proc_exe(uint32_t pid,const char*expected,const char*hash,unsigned char digest[32]){
 char name[64],target[128];snprintf(name,sizeof name,"/proc/%u/exe",pid);ssize_t n=readlink(name,target,sizeof target);if(n<0||(size_t)n!=strlen(expected)||memcmp(target,expected,n))return 0;
 int fd=open(name,O_RDONLY|O_CLOEXEC);if(fd<0)return 0;struct stat a,b;int okay=0;unsigned char buf[4096];struct sha256 h;sha_init(&h);
 if(fstat(fd,&a)||!S_ISREG(a.st_mode)||a.st_size<=0||a.st_size>512*1024)goto end;
 off_t left=a.st_size;while(left){size_t ask=left>4096?4096:(size_t)left;ssize_t r=read(fd,buf,ask);if(r<0&&errno==EINTR)continue;if(r<=0)goto end;left-=r;sha_add(&h,buf,r);}ssize_t r;do{r=read(fd,buf,1);}while(r<0&&errno==EINTR);if(r||fstat(fd,&b)||a.st_ino!=b.st_ino||a.st_dev!=b.st_dev||a.st_size!=b.st_size)goto end;
 sha_end(&h,digest);okay=1;for(unsigned i=0;i<32;i++){const char*hex="0123456789abcdef";if(hex[digest[i]>>4]!=hash[2*i]||hex[digest[i]&15]!=hash[2*i+1])okay=0;}
 end:if(close(fd))okay=0;return okay;
}
static uint64_t mono(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return 0;return(uint64_t)t.tv_sec*1000000000+(uint32_t)t.tv_nsec;}
static int qualify(struct bo_record*r){
 if(geteuid()!=0)return 10;r->launcher_pid=1;r->shell_pid=getppid();r->observer_parent=getpid();r->uid=geteuid();uint32_t parent=99;uint64_t start=0;
 if(!proc_stat(1,&parent,&r->launcher_start)||parent!=0||!proc_exe(1,"/usr/bin/launch_shell.elf",launcher_hash,r->launcher_sha))return 11;
 if(!proc_stat(r->shell_pid,&parent,&r->shell_start)||parent!=1||!proc_exe(r->shell_pid,"/bin/busybox",shell_hash,r->shell_sha))return 12;
 char path[64],cmd[64];snprintf(path,sizeof path,"/proc/%u/cmdline",r->shell_pid);const char expected[]="/bin/ash\0--login";int n=bounded_read(path,cmd,sizeof cmd);if(n!=(int)sizeof expected||memcmp(cmd,expected,n))return 13;
 if(getppid()!=(pid_t)r->shell_pid||!proc_stat(r->shell_pid,&parent,&start)||parent!=1||start!=r->shell_start)return 14;r->ancestry_qualified=1;return 0;
}
static void im_observe(struct bo_record*r){DIR*d=opendir("/proc");if(!d){r->flags|=4;return;}struct dirent*e;unsigned count=0;while((e=readdir(d))&&count++<8192){uint64_t pid;if(!decimal(e->d_name,e->d_name+strlen(e->d_name),&pid)||!pid||pid>INT32_MAX)continue;char path[64],target[128];snprintf(path,sizeof path,"/proc/%u/exe",(unsigned)pid);ssize_t n=readlink(path,target,sizeof target);const char expected[]="/usr/bin/im.elf";if(n!=(int)sizeof expected-1||memcmp(target,expected,n))continue;unsigned char digest[32];uint32_t pp;uint64_t start;if(!proc_exe(pid,expected,im_hash,digest)||!proc_stat(pid,&pp,&start)){r->flags|=8;continue;}r->im_seen++;r->im_pid=pid;r->im_start=start;}if(count>=8192)r->flags|=16;if(closedir(d))r->flags|=32;}
static int private_dir(void){int base=open("/tmp",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(base<0)return-1;struct statfs fs;if(fstatfs(base,&fs)||fs.f_type!=0x4d44){close(base);return-1;}if(mkdirat(base,BO_DIR,0700)&&errno!=EEXIST){close(base);return-1;}int fd=openat(base,BO_DIR,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);int c=close(base);struct stat st;if(fd<0)return-1;if(c||fstat(fd,&st)||st.st_uid!=0||(st.st_mode&07777)!=0700){close(fd);return-1;}return fd;}
static int write_record(int dir,struct bo_record*r){int fd=openat(dir,"record.bin",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0400);if(fd<0)return 30;size_t left=sizeof *r,at=0;int rc=0;while(left){ssize_t n=write(fd,(char*)r+at,left);if(n<0&&errno==EINTR)continue;if(n<=0){rc=31;break;}at+=n;left-=n;}if(!rc&&fsync(fd))rc=32;if(close(fd))rc=33;if(!rc&&fsync(dir))rc=34;return rc;}
