/* Host ASan/UBSan 35-scenario boot-guard V21 transaction & fault-injection suite. */
#define _GNU_SOURCE
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int fault_renameat(int, const char*, int, const char*);
int fault_fsync(int);
ssize_t fault_write(int, const void*, size_t);
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
#include "../boot-guard/transaction.c"
#undef fstat
#undef renameat
#undef fsync
#undef write

static unsigned scenario,checks,failures,rw_calls,ro_calls;static int readonly,libfd,active;
static int rename_success,held_target=-1;
static unsigned char original[128],candidate[160];
static void ck(int ok,const char*why){checks++;if(!ok){failures++;printf("FAIL case=%u %s\n",scenario,why);}}
static void hash(const void*p,unsigned n,unsigned char out[32]){struct sha256 s;sha_init(&s);sha_add(&s,p,n);sha_end(&s,out);}
static void put(int d,const char*n,const void*b,unsigned length,unsigned mode){int f=openat(d,n,O_CREAT|O_EXCL|O_WRONLY,mode);if(f<0||write(f,b,length)!=(ssize_t)length||fsync(f)||close(f))exit(90);}
static int mount_port(void*x,int mode){(void)x;if(mode){ro_calls++;if(scenario==17)return -1;struct stat t;if(held_target>=0&&(fstat(held_target,&t)||t.st_nlink==0))return -1;readonly=1;}else{rw_calls++;if(scenario==15)return -1;readonly=0;}return 0;}
static int ro_port(void*x){(void)x;return readonly;}
static int process_port(void*x,uint32_t pid,uint64_t start){(void)x;return pid==151&&start==106&&scenario!=4;}
int fault_renameat(int olddir,const char*old,int newdir,const char*name){if(active&&scenario==16){errno=EIO;return -1;}int r=renameat(olddir,old,newdir,name);if(!r)rename_success=1;return r;}
int fault_fsync(int fd){if(active&&scenario==18&&fd==libfd&&rename_success){errno=EIO;return -1;}return fsync(fd);}
ssize_t fault_write(int fd,const void*b,size_t n){if(active&&scenario==19){errno=ENOSPC;return -1;}return write(fd,b,n);}
static void record(int dir,const char*name,const struct gx_config*c,uint64_t seq,unsigned phase,int oldboot){
 struct gx_record r={.abi=1,.bytes=256,.seq=seq,.phase=phase,.code=phase==GX_READY?c->ready_build:0,.pid=151};
 memcpy(r.magic,"A7GXST01",8);memcpy(r.nonce,c->nonce,16);memcpy(r.candidate,c->candidate,32);memcpy(r.boot,c->boot,40);if(oldboot)r.boot[0]='b';
 if(phase==GX_READY){uint64_t start=106;memcpy(r.extra,&start,8);}
 if(scenario==3)r.nonce[1]^=1;gx_seal(&r);put(dir,name,&r,256,0600);
}
static pid_t changer(int journal,int lib,unsigned which){pid_t p=fork();if(p)return p;struct stat s;for(unsigned i=0;i<100;i++){if(!fstatat(journal,"state.a",&s,0)&&s.st_size==256)break;usleep(5000);}usleep(20000);
 const char*target=which==22?"target.so":"standby.so";const void*b=which==22?(void*)candidate:(void*)original;unsigned n=which==22?sizeof candidate:sizeof original;
 put(lib,"change.tmp",b,n,0555);if(renameat(lib,"change.tmp",lib,target))_exit(99);_exit(0);}
int main(void){
 setbuf(stdout,NULL);for(unsigned i=0;i<sizeof original;i++)original[i]=i^0x93;for(unsigned i=0;i<sizeof candidate;i++)candidate[i]=i^0x72;
 char root_tpl[]="/tmp/a7r-guard-orig-XXXXXX";char*root=mkdtemp(root_tpl);if(!root)return 91;
 int base=open(root,O_RDONLY|O_DIRECTORY);if(base<0)return 91;
 for(scenario=0;scenario<35;scenario++){
  char name[32];snprintf(name,sizeof name,"case%02u",scenario);if(mkdirat(base,name,0700))return 92;int dir=openat(base,name,O_RDONLY|O_DIRECTORY);if(dir<0)return 92;
  if(mkdirat(dir,"lib",0700)||mkdirat(dir,"journal",0700))return 93;libfd=openat(dir,"lib",O_RDONLY|O_DIRECTORY);int journal=openat(dir,"journal",O_RDONLY|O_DIRECTORY);if(libfd<0||journal<0)return 93;
  struct gx_config c={.target="target.so",.standby="standby.so",.retained="retired.so",.original_bytes=sizeof original,.candidate_bytes=sizeof candidate,.mode=0555,.uid=0,.gid=0,.wait_ms=100,.ready_build=0x3010e102,.remount=mount_port,.readonly=ro_port,.ready_process=process_port};
  c.nonce[0]=1;c.nonce[1]=scenario+1;strcpy(c.boot,"aaaaaaaa-1111-2222-3333-444444444444");hash(original,sizeof original,c.original);hash(candidate,sizeof candidate,c.candidate);
  put(libfd,"target.so",(scenario==6||scenario==30)?(void*)original:(void*)candidate,(scenario==6||scenario==30)?sizeof original:sizeof candidate,0555);put(libfd,"standby.so",scenario==7?(void*)candidate:(void*)original,scenario==7?sizeof candidate:sizeof original,0555);
  if(scenario==5||scenario==32)c.candidate[0]^=1;
  if(scenario>=29)c.force_recovery=scenario==31?2:1;
  if(scenario==29||scenario==33||scenario==34){record(journal,"state.a",&c,1,GX_ACCEPTED,0);record(journal,"ready.bin",&c,1,GX_READY,0);}
  if(scenario==33&&linkat(libfd,"target.so",libfd,"retired.so",0))return 98;
  if(scenario>=1&&scenario<=4)record(journal,"ready.bin",&c,1,GX_READY,scenario==2);
  if(scenario==8)record(journal,"state.a",&c,1,GX_STARTED,0);
  if(scenario==9||scenario==10)record(journal,"state.a",&c,1,GX_ACCEPTED,scenario==9);
  if(scenario==11)put(journal,"state.a",candidate,17,0600);
  if(scenario==12){record(journal,"state.a",&c,1,GX_ACCEPTED,1);record(journal,"state.b",&c,4,GX_ACCEPTED,1);}
  if(scenario==13){if(unlinkat(libfd,"target.so",0)||symlinkat("standby.so",libfd,"target.so"))return 94;}
  if(scenario==14){if(linkat(libfd,"standby.so",libfd,"alias.so",0))return 94;}
  if(scenario==20)record(journal,"state.a",&c,1,GX_READY,0);
  if(scenario==21)record(journal,"state.a",&c,1,GX_DONE,1);
  if(scenario==24)put(journal,"ready.bin",candidate,64,0600);
  if(scenario==26){if(linkat(libfd,"target.so",libfd,"retired.so",0))return 98;record(journal,"state.a",&c,1,GX_RESTORE_INTENT,1);}
  if(scenario==27)put(libfd,"retired.so",original,sizeof original,0555);
  if(scenario==28){if(linkat(libfd,"target.so",libfd,"alias.so",0))return 98;}
  pid_t actor=-1;if(scenario==22||scenario==23)actor=changer(journal,libfd,scenario);
  held_target=openat(libfd,"target.so",O_RDONLY);if(held_target<0)return 99;readonly=1;rw_calls=ro_calls=0;rename_success=0;active=1;struct gx_result out;gx_run(libfd,journal,&c,&out);active=0;
  if(actor>0){int status=-1;ck(waitpid(actor,&status,0)==actor&&status==0,"changer exited");}
  unsigned expected=(scenario==1||scenario==10)?GX_CONFIRMED:scenario==31?GX_INVALID:scenario==5||scenario==13||scenario==32?GX_TARGET:scenario==6||scenario==30?GX_STOCK:scenario==7||scenario==14?GX_SOURCE:scenario==15?GX_MOUNT:scenario==16?GX_RENAME:scenario==17?GX_READONLY:scenario==18?GX_DURABILITY:scenario==22||scenario==23?GX_CHANGED:scenario==27||scenario==28?GX_RETAIN:GX_RESTORED;
  ck(out.code==expected,"result code");ck(rw_calls<=1&&ro_calls==rw_calls,"single remount pair");ck(out.readonly==(scenario!=17),"readonly observed");
  int restored=expected==GX_RESTORED||scenario==17||scenario==18;ck(out.restored==(unsigned)restored,"restored count");
  if(restored){struct stat keep;ck(!fstatat(libfd,"retired.so",&keep,0)&&keep.st_nlink==1,"mapped old candidate retains a directory link");}
  int f=openat(libfd,"target.so",O_RDONLY);unsigned char got[161];ssize_t n=f<0?-1:read(f,got,sizeof got);if(f>=0)close(f);int stock=restored||scenario==6||scenario==13||scenario==30;
  ck(n==(ssize_t)(stock?sizeof original:sizeof candidate),"full target length");ck(!memcmp(got,stock?original:candidate,(size_t)n),"full target contents");
  if(scenario==19)ck(out.journal_error,"journal ENOSPC reported while exact standby restored");
  if(scenario==29||scenario==33||scenario==34)ck(out.reason==6&&!out.ready,"forced recovery overrides prior acceptance only after authentication");
  if(scenario==25||scenario==34){struct gx_result again;active=1;unsigned before=rw_calls;gx_run(libfd,journal,&c,&again);active=0;ck(again.code==GX_STOCK&&!again.restored&&rw_calls==before,"completed restore never repeated");}
  if(close(held_target))return 99;held_target=-1;
  const char*files[]={"target.so","standby.so","alias.so","change.tmp","retired.so"};for(unsigned i=0;i<5;i++)if(unlinkat(libfd,files[i],0)&&errno!=ENOENT)return 95;
  const char*records[]={"state.a","state.b","ready.bin"};for(unsigned i=0;i<3;i++)if(unlinkat(journal,records[i],0)&&errno!=ENOENT)return 95;
  if(close(libfd)||close(journal)||unlinkat(dir,"lib",AT_REMOVEDIR)||unlinkat(dir,"journal",AT_REMOVEDIR)||close(dir)||unlinkat(base,name,AT_REMOVEDIR))return 96;
 }
 close(base);rmdir(root);
 printf("GX_COMPLETE cases=35 checks=%u failures=%u mount_ports=fixture real_firmware_target=0\n",checks,failures);return failures?1:0;
}
