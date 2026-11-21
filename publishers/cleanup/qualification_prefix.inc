/* Fixed optional-touch owner publication; no feature execution or reboot.
 * Registry, accepted audio/menu, guard and installation nonce stay byte exact.
 * Existing inode-retaining gi_run is reused without modification. */
#define _GNU_SOURCE
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/mount.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "../commit/install.c"
#include "publication_identity.h"
static int usr=-1,lib=-1,journal=-1;
static unsigned qualification_stage;
struct epoch {char boot[40];uint32_t pid;uint64_t start;};
static int qualify(const struct epoch*);
static int hex32(const char*s,unsigned char out[32]){if(strlen(s)!=64)return 0;for(unsigned i=0;i<32;i++){unsigned v;if(sscanf(s+2*i,"%2x",&v)!=1)return 0;out[i]=(unsigned char)v;}return 1;}
static int bounded(const char*p,char*b,unsigned cap){int f=open(p,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(f<0)return -1;unsigned n=0,calls=0;int good=1;while(n+1<cap&&calls++<1024){ssize_t r=read(f,b+n,cap-n-1);if(r<0&&errno==EINTR)continue;if(r<0){good=0;break;}if(!r)break;n+=(unsigned)r;}char tail;if(read(f,&tail,1))good=0;if(close(f))good=0;b[n]=0;return good?(int)n:-1;}
static int ro(void*x){(void)x;struct stat s;struct statfs f;if(usr<0||fstat(usr,&s)||!S_ISDIR(s.st_mode)||s.st_uid||major(s.st_dev)!=252||minor(s.st_dev)!=15||fstatfs(usr,&f)||f.f_type!=0xef53)return -1;return !!(f.f_flags&MS_RDONLY);}
static int remount(void*x,int readonly){
 /* A failed last qualification may block RW; it must NEVER block RO restore. */
 if(ro(0)<0||(!readonly&&!qualify(x)))return -1;
 return mount(0,"/usr",0,MS_REMOUNT|MS_RELATIME|(readonly?MS_RDONLY:0),0);
}
static int dependency(const char*path,unsigned bytes,unsigned uid,unsigned gid,unsigned mode,const char*hash){int f=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);struct identity i;unsigned char want[32];int good=f>=0&&hex32(hash,want)&&!identify(f,&i)&&i.s.st_size==bytes&&i.s.st_uid==uid&&i.s.st_gid==gid&&i.s.st_mode==(S_IFREG|mode)&&i.s.st_nlink==1&&major(i.s.st_dev)==252&&minor(i.s.st_dev)==15&&!memcmp(i.hash,want,32);if(f>=0&&close(f))good=0;return good;}
static int image_identity(const char*path){
 int f=open(path,O_RDONLY|O_CLOEXEC);if(f<0)return 0;struct stat a={0},b={0};unsigned char want[32]={0},digest[32],block[4096];struct sha256 h;sha_init(&h);int good=!fstat(f,&a)&&S_ISREG(a.st_mode)&&a.st_size>0&&a.st_size<64*1024*1024&&hex32("866729eb0bc1e6f5aba04d8bf8e45491985afe89a078ccb106a1ce2476865225",want);off_t left=good?a.st_size:0;unsigned calls=0;
 while(good&&left&&calls++<32768){ssize_t n=read(f,block,left>4096?4096:(size_t)left);if(n<0&&errno==EINTR)continue;if(n<=0){good=0;break;}sha_add(&h,block,n);left-=n;}char more;if(left||read(f,&more,1)!=0||fstat(f,&b)||a.st_dev!=b.st_dev||a.st_ino!=b.st_ino||a.st_size!=b.st_size||a.st_mode!=b.st_mode||a.st_uid!=b.st_uid||a.st_gid!=b.st_gid)good=0;sha_end(&h,digest);if(memcmp(digest,want,32))good=0;if(close(f))good=0;return good;
}
static int proc_epoch(const struct epoch*e){char p[80],b[2048];if(bounded("/proc/sys/kernel/random/boot_id",b,sizeof b)!=37||memcmp(b,e->boot,36)||b[36]!='\n')return 0;snprintf(p,sizeof p,"/proc/%u/stat",e->pid);if(bounded(p,b,sizeof b)<0)return 0;unsigned id=0;if(sscanf(b,"%u",&id)!=1||id!=e->pid)return 0;char*q=strrchr(b,')');if(!q||q[1]!=' ')return 0;q+=2;uint64_t parent=0,start=0;for(unsigned field=3;*q&&field<=22;field++){char*n=strchr(q,' ');if(field==4)parent=strtoull(q,0,10);if(field==22)start=strtoull(q,0,10);if(!n)break;q=n+1;}if(parent!=1||start!=e->start)return 0;snprintf(p,sizeof p,"/proc/%u/exe",e->pid);ssize_t n=readlink(p,b,sizeof b);return n==15&&!memcmp(b,"/usr/bin/im.elf",15)&&image_identity(p);}
static int qualified_ready(const struct epoch*e){struct gx_config c={.ready_build=0x3110f20e};memcpy(c.nonce,accepted_installation,16);memcpy(c.boot,e->boot,40);if(!hex32(ACCEPTED_REGISTRY_SHA,c.candidate))return 0;struct gx_record r,a,b;int av=read_record(journal,"state.a",&a),bv=read_record(journal,"state.b",&b);if(av!=1||bv!=1||!gx_valid(&a,&c)||!gx_valid(&b,&c)||(a.seq>b.seq?a.seq-b.seq:b.seq-a.seq)!=1)return 0;struct gx_record*s=a.seq>b.seq?&a:&b,*previous=a.seq>b.seq?&b:&a;if(s->pid<2||s->pid!=previous->pid||s->phase!=GX_ACCEPTED||s->code||previous->phase!=GX_STARTED||previous->code||memcmp(a.boot,e->boot,40)||memcmp(b.boot,e->boot,40)||read_record(journal,"ready.bin",&r)!=1||!gx_valid(&r,&c)||r.phase!=GX_READY||r.seq!=1||r.code!=c.ready_build||memcmp(r.boot,e->boot,40)||r.pid!=e->pid||memcmp(r.extra,&e->start,8))return 0;return 1;}
static int qualify(const struct epoch*e){struct stat s;qualification_stage=1;
 if(!e||geteuid()||fstat(lib,&s)||!S_ISDIR(s.st_mode)||s.st_ino!=49345||s.st_uid!=57285||s.st_gid!=1000||(s.st_mode&07777)!=0755||major(s.st_dev)!=252||minor(s.st_dev)!=15||fstat(journal,&s)||!S_ISDIR(s.st_mode)||s.st_uid||s.st_gid||(s.st_mode&07777)!=0700)return 0;
 qualification_stage=2;if(!proc_epoch(e))return 0;
 qualification_stage=3;if(!qualified_ready(e))return 0;
 for(unsigned i=0;i<sizeof immutable_dependencies/sizeof immutable_dependencies[0];i++){qualification_stage=100+i;const struct dep*d=&immutable_dependencies[i];if(!dependency(d->path,d->bytes,d->uid,d->gid,d->mode,d->hash))return 0;}
 qualification_stage=4;if(!proc_epoch(e)||!qualified_ready(e))return 0;
 qualification_stage=0;return 1;
}
static int uuid(const char*s){if(strlen(s)!=36)return 0;for(unsigned i=0;i<36;i++){char c=s[i];if(i==8||i==13||i==18||i==23){if(c!='-')return 0;}else if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')))return 0;}return 1;}
