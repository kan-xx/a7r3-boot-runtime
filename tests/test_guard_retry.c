/* Host ASan/UBSan V17 narrow 1-boot retry + fork/_exit power-cut test suite. */
#define _GNU_SOURCE
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <time.h>

int fault_renameat(int, const char*, int, const char*);
int fault_fsync(int);
ssize_t fault_write(int, const void*, size_t);
int fault_fstatat(int, const char*, struct stat*, int);
#ifdef __APPLE__
static int fixture_fstat(int fd, struct stat* s) {
 int rc = fstat(fd, s);
 if (!rc) { s->st_uid = 0; s->st_gid = 0; }
 return rc;
}
#define fstat fixture_fstat
#endif
#define renameat fault_renameat
#define fsync fault_fsync
#define write fault_write
#define fstatat fault_fstatat
#include "../boot-guard/transaction.c"
#undef fstat
#undef renameat
#undef fsync
#undef write
#undef fstatat

static const char A[]="aaaaaaaa-1111-2222-3333-444444444444",B[]="bbbbbbbb-1111-2222-3333-444444444444",CBOOT[]="cccccccc-1111-2222-3333-444444444444",DBOOT[]="dddddddd-1111-2222-3333-444444444444";
static unsigned checks,cases,failures,rw_calls,ro_calls;static int readonly=1,active,cut_mode,fail_mode,fail_fd=-1,stat_error;
static unsigned char original[128],candidate[160];static int libfd,journal,rootfd,heldfd;
static struct gx_config c;
#define CK(v)do{checks++;if(!(v)){failures++;fprintf(stderr,"FAIL case%u line%u: %s\n",cases,__LINE__,#v);}}while(0)
static void digest(const void*p,unsigned n,unsigned char*out){struct sha256 s;sha_init(&s);sha_add(&s,p,n);sha_end(&s,out);}
static void put(int d,const char*n,const void*p,unsigned z,unsigned mode){int fd=openat(d,n,O_WRONLY|O_CREAT|O_EXCL,mode);if(fd<0||write(fd,p,z)!=(ssize_t)z||fsync(fd)||close(fd))abort();}
int fault_fstatat(int fd,const char*name,struct stat*s,int flags){if(active&&stat_error&&!strncmp(name,"failure-",8)){errno=stat_error;return -1;}return fstatat(fd,name,s,flags);}
int fault_fsync(int fd){if(active&&fail_mode==2&&fd==fail_fd){fail_mode=0;errno=EIO;return -1;}return fsync(fd);}
int fault_renameat(int a,const char*b,int d,const char*n){return renameat(a,b,d,n);}
ssize_t fault_write(int fd,const void*p,size_t n){
 if(active&&n==256&&!memcmp(p,"A7GXST01",8)&&((const struct gx_record*)p)->phase==GX_STARTED){
  if(cut_mode==1){if(write(fd,p,n)!=(ssize_t)n)_exit(99);_exit(77);}
  if(cut_mode==2){if(write(fd,p,17)!=17)_exit(99);_exit(79);}
  if(fail_mode==1){fail_mode=0;errno=ENOSPC;return -1;}
  if(fail_mode==2)fail_fd=fd;
 }
 return write(fd,p,n);
}
static int remount_port(void*x,int ro){(void)x;if(ro)ro_calls++;else rw_calls++;readonly=ro;return 0;}
static int ro_port(void*x){(void)x;return readonly;}
static int process_port(void*x,uint32_t pid,uint64_t start){(void)x;if(cut_mode==3)_exit(78);return pid==151&&start==106;}
static void record(const char*name,uint64_t seq,unsigned phase,const char*boot,uint32_t pid,uint64_t start){struct gx_record r={.abi=1,.bytes=256,.seq=seq,.phase=phase,.code=phase==GX_READY?c.ready_build:0,.pid=pid};memcpy(r.magic,"A7GXST01",8);memcpy(r.nonce,c.nonce,16);memcpy(r.candidate,c.candidate,32);memcpy(r.boot,boot,37);if(phase==GX_READY)memcpy(r.extra,&start,8);gx_seal(&r);put(journal,name,&r,sizeof r,0600);}
static void fresh(const char*root,unsigned prev,unsigned latest,int sameboot){
 char path[256];snprintf(path,sizeof path,"%s/case%02u",root,++cases);if(mkdir(path,0700))abort();rootfd=open(path,O_RDONLY|O_DIRECTORY);if(rootfd<0||mkdirat(rootfd,"lib",0700)||mkdirat(rootfd,"journal",0700))abort();libfd=openat(rootfd,"lib",O_RDONLY|O_DIRECTORY);journal=openat(rootfd,"journal",O_RDONLY|O_DIRECTORY);if(libfd<0||journal<0)abort();
 c=(struct gx_config){.target="target.so",.standby="standby.so",.retained="retired.so",.original_bytes=128,.candidate_bytes=160,.mode=0555,.uid=0,.gid=0,.wait_ms=100,.ready_build=0x3110f20e,.remount=remount_port,.readonly=ro_port,.ready_process=process_port};memcpy(c.boot,CBOOT,37);c.nonce[0]=1;digest(original,128,c.original);digest(candidate,160,c.candidate);put(libfd,c.target,candidate,160,0555);put(libfd,c.standby,original,128,0555);heldfd=openat(libfd,c.target,O_RDONLY);if(heldfd<0)abort();
 if(prev)record("state.b",2,prev,B,158,0);if(latest)record("state.a",3,latest,sameboot?CBOOT:A,158,0);
 readonly=1;rw_calls=ro_calls=0;active=cut_mode=fail_mode=stat_error=0;fail_fd=-1;
}
static struct gx_result run(void){struct gx_result r;active=1;gx_run(libfd,journal,&c,&r);active=0;return r;}
static void clear_dir(int fd){DIR*d=fdopendir(dup(fd));struct dirent*e;if(!d)abort();while((e=readdir(d))){if(!strcmp(e->d_name,".")||!strcmp(e->d_name,".."))continue;struct stat s;if(fstatat(fd,e->d_name,&s,AT_SYMLINK_NOFOLLOW)||unlinkat(fd,e->d_name,S_ISDIR(s.st_mode)?AT_REMOVEDIR:0))abort();}if(closedir(d))abort();}
static void finish(const char*root,const struct gx_result*r,unsigned code,unsigned reason){
 CK(r->code==code&&r->reason==reason);CK(r->readonly==1&&readonly==1);CK(rw_calls<=1&&ro_calls==rw_calls);
 int f=openat(libfd,c.target,O_RDONLY);unsigned char b[161];ssize_t n=f<0?-1:read(f,b,sizeof b);if(f>=0)close(f);int stock=code==GX_RESTORED;CK(n==(stock?128:160));CK(n>0&&!memcmp(b,stock?original:candidate,(unsigned)n));CK(r->restored==(unsigned)stock);
 if(stock){struct stat s;CK(!fstat(heldfd,&s)&&s.st_nlink==1);CK(!fstatat(libfd,c.retained,&s,0)&&s.st_nlink==1);}
 if(close(heldfd))abort();clear_dir(libfd);clear_dir(journal);if(close(libfd)||close(journal)||unlinkat(rootfd,"lib",AT_REMOVEDIR)||unlinkat(rootfd,"journal",AT_REMOVEDIR)||close(rootfd))abort();char path[256];snprintf(path,sizeof path,"%s/case%02u",root,cases);if(rmdir(path))abort();
}
static void failure_file(const char*boot,const char*suffix,int kind){char name[64];snprintf(name,sizeof name,"failure-%s.%s",boot,suffix);if(kind==1){if(symlinkat("unavailable",journal,name))abort();}else if(kind==2){if(mkdirat(journal,name,0700))abort();}else put(journal,name,"partial",7,0600);}
static void change_record(const char*name,unsigned code,const char*boot){int f=openat(journal,name,O_RDWR);struct gx_record r;if(f<0||read(f,&r,256)!=256)abort();r.code=code;if(boot)memcpy(r.boot,boot,37);gx_seal(&r);if(pwrite(f,&r,256,0)!=256||fsync(f)||close(f))abort();}
static void cut_child(unsigned mode){pid_t child=fork();if(child<0)abort();if(!child){cut_mode=mode;(void)run();_exit(99);}int status=0;CK(waitpid(child,&status,0)==child);CK(WIFEXITED(status)&&WEXITSTATUS(status)==(mode==1?77:mode==2?79:78));}
int main(void){
 char tpl[]="/tmp/a7r-guard-retry-XXXXXX";char*root=mkdtemp(tpl);if(!root)return 90;
 for(unsigned i=0;i<128;i++)original[i]=i^0x93;for(unsigned i=0;i<160;i++)candidate[i]=i^0x72;struct gx_result r;
 fresh(root,GX_ACCEPTED,GX_STARTED,0);record("ready.bin",1,GX_READY,CBOOT,151,106);r=run();CK(r.ready&&r.sequence==5&&rw_calls==0);struct gx_record x,y;int fa=openat(journal,"state.a",O_RDONLY),fb=openat(journal,"state.b",O_RDONLY);CK(fa>=0&&fb>=0&&read(fa,&x,256)==256&&read(fb,&y,256)==256);close(fa);close(fb);CK(x.phase==GX_ACCEPTED&&x.seq==5&&y.phase==GX_STARTED&&y.seq==4&&!memcmp(x.boot,c.boot,40));finish(root,&r,GX_CONFIRMED,0);
 fresh(root,GX_ACCEPTED,GX_STARTED,0);cut_child(1);memcpy(c.boot,DBOOT,37);record("ready.bin",1,GX_READY,DBOOT,151,106);r=run();finish(root,&r,GX_RESTORED,2);
 fresh(root,GX_ACCEPTED,GX_STARTED,0);record("ready.bin",1,GX_READY,CBOOT,151,106);cut_child(3);memcpy(c.boot,DBOOT,37);r=run();finish(root,&r,GX_RESTORED,2);
 fresh(root,GX_ACCEPTED,GX_STARTED,0);cut_child(2);memcpy(c.boot,DBOOT,37);r=run();finish(root,&r,GX_RESTORED,1);
 fresh(root,GX_ACCEPTED,GX_STARTED,1);record("ready.bin",1,GX_READY,CBOOT,151,106);r=run();finish(root,&r,GX_RESTORED,2);
 fresh(root,0,GX_STARTED,0);record("ready.bin",1,GX_READY,CBOOT,151,106);r=run();finish(root,&r,GX_RESTORED,2);
 fresh(root,GX_ACCEPTED,GX_STARTED,0);memcpy(c.boot,B,37);record("ready.bin",1,GX_READY,B,151,106);r=run();finish(root,&r,GX_RESTORED,2);
 fresh(root,GX_ACCEPTED,GX_STARTED,0);change_record("state.a",0,B);record("ready.bin",1,GX_READY,CBOOT,151,106);r=run();finish(root,&r,GX_RESTORED,2);
 fresh(root,GX_ACCEPTED,GX_STARTED,0);change_record("state.a",1,0);record("ready.bin",1,GX_READY,CBOOT,151,106);r=run();finish(root,&r,GX_RESTORED,2);
 fresh(root,GX_ACCEPTED,GX_STARTED,0);change_record("state.b",1,0);record("ready.bin",1,GX_READY,CBOOT,151,106);r=run();finish(root,&r,GX_RESTORED,2);
 for(unsigned phase=1;phase<=6;phase++){if(phase==GX_ACCEPTED)continue;fresh(root,phase,GX_STARTED,0);record("ready.bin",1,GX_READY,CBOOT,151,106);r=run();finish(root,&r,GX_RESTORED,2);}
 for(unsigned phase=3;phase<=6;phase++){fresh(root,GX_ACCEPTED,phase,0);record("ready.bin",1,GX_READY,CBOOT,151,106);r=run();finish(root,&r,GX_RESTORED,2);}
 fresh(root,GX_ACCEPTED,GX_STARTED,0);c.force_recovery=1;record("ready.bin",1,GX_READY,CBOOT,151,106);r=run();finish(root,&r,GX_RESTORED,6);
 const char*boots[]={A,B,CBOOT};for(unsigned i=0;i<3;i++)for(unsigned j=0;j<2;j++){fresh(root,GX_ACCEPTED,GX_STARTED,0);failure_file(boots[i],j?"new":"bin",0);record("ready.bin",1,GX_READY,CBOOT,151,106);r=run();finish(root,&r,GX_RESTORED,2);}
 for(int kind=1;kind<=2;kind++){fresh(root,GX_ACCEPTED,GX_STARTED,0);failure_file(A,"bin",kind);r=run();finish(root,&r,GX_RESTORED,2);}
 fresh(root,GX_ACCEPTED,GX_STARTED,0);stat_error=EACCES;r=run();stat_error=0;finish(root,&r,GX_RESTORED,2);
 for(unsigned fail=1;fail<=2;fail++){fresh(root,GX_ACCEPTED,GX_STARTED,0);fail_mode=fail;record("ready.bin",1,GX_READY,CBOOT,151,106);r=run();CK(r.journal_error);finish(root,&r,GX_RESTORED,3);}
 fresh(root,GX_ACCEPTED,GX_STARTED,0);r=run();finish(root,&r,GX_RESTORED,5);
 fresh(root,GX_ACCEPTED,GX_STARTED,0);record("ready.bin",1,GX_READY,A,151,106);r=run();CK(r.invalid_ready>0);finish(root,&r,GX_RESTORED,5);
 fresh(root,GX_ACCEPTED,GX_STARTED,0);record("ready.bin",1,GX_READY,CBOOT,152,106);r=run();CK(r.invalid_ready>0);finish(root,&r,GX_RESTORED,5);
 fresh(root,GX_ACCEPTED,GX_STARTED,0);record("ready.bin",1,GX_READY,CBOOT,151,107);r=run();CK(r.invalid_ready>0);finish(root,&r,GX_RESTORED,5);
 if(rmdir(root))abort();printf("RETRY_E2E cases=%u checks=%u failures=%u native_filesystem=1 remount=fixture target_camera=0\n",cases,checks,failures);return failures?1:0;
}
