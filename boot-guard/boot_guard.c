/* Independent boot recovery, retained after READY for explicit authenticated
 * runtime failures. This is not an arbitrary-hang detector. */
#define _GNU_SOURCE
#include "startup_prefix.c"
#include "transaction.h"
#include "monitor.h"
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/sysmacros.h>
#include "configuration.h"
static int root_fd=-1;
static int ro(void*context) {
 (void)context;struct stat st;struct statfs fs;
 if(root_fd<0||fstat(root_fd,&st)||!S_ISDIR(st.st_mode)||st.st_uid||major(st.st_dev)!=252||minor(st.st_dev)!=15||fstatfs(root_fd,&fs)||fs.f_type!=0xef53)return -1;
 return !!(fs.f_flags&MS_RDONLY);
}
static int remount_usr(void*context,int readonly) {
 (void)context;if(ro(0)<0)return -1;
 return mount(NULL,"/usr",NULL,MS_REMOUNT|MS_RELATIME|(readonly?MS_RDONLY:0),NULL);
}
static int live_im(void*context,uint32_t pid,uint64_t expected_start) {
 (void)context;uint32_t parent=0;uint64_t start=0;unsigned char digest[32];
 return proc_stat(pid,&parent,&start)&&parent==1&&start==expected_start&&proc_exe(pid,"/usr/bin/im.elf",im_hash,digest);
}
static int no_snapshot_restart(void) {
 char b[32];int n=bounded_read("/sys/power/image_dev",b,sizeof b);if(n!=6||memcmp(b,"*wbi4\n",6))return -1;
 int f=open("/sys/power/image_mode",O_WRONLY|O_CLOEXEC);if(f<0)return -1;
 int okay=write(f,"0",1)==1;if(close(f))okay=0;if(!okay)return -1;
 n=bounded_read("/sys/power/image_mode",b,sizeof b);return n==2&&!memcmp(b,"0\n",2)?0:-1;
}
int main(void) {
 struct bo_record r={.magic=BO_MAGIC,.abi=1,.build=BO_BUILD,.bytes=sizeof r};memcpy(r.installation,installation,16);r.mono_begin_ns=mono();int rc=qualify(&r);if(rc)return rc;
 if(!r.mono_begin_ns)return 15;int dir=private_dir();if(dir<0)return 16;
 int lock=openat(dir,"observer.lock",O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC,0600);struct stat st;
 if(lock<0||fstat(lock,&st)||!S_ISREG(st.st_mode)||st.st_uid||st.st_gid||st.st_nlink!=1||(st.st_mode&07777)!=0600||flock(lock,LOCK_EX|LOCK_NB)){if(lock>=0)close(lock);close(dir);return 17;}
 pid_t child=fork();if(child<0){close(lock);close(dir);return 22;}if(child){close(lock);close(dir);return 0;}
 r.worker_pid=getpid();r.worker_ppid_before=getppid();if(setsid()<0)r.flags|=1;
 long maxfd=sysconf(_SC_OPEN_MAX);if(maxfd<0||maxfd>4096)maxfd=4096;for(int f=0;f<maxfd;f++)if(f!=dir&&f!=lock)close(f);
 struct timespec pause={0,20000000};for(unsigned i=0;i<50&&getppid()!=1;i++){if(nanosleep(&pause,0))r.flags|=2;}
 r.worker_ppid_after=getppid();if(r.worker_ppid_after!=1)r.flags|=2;
 int n=bounded_read("/proc/sys/kernel/random/boot_id",r.boot_id,sizeof r.boot_id);if(n==37&&r.boot_id[36]=='\n'){r.boot_id[36]=0;r.boot_id_bytes=36;}else r.flags|=64;
 struct gx_result result={.code=GX_INVALID};int lib=-1;struct gx_config c=configuration;
 if(!r.flags){root_fd=open("/usr",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
  if(ro(0)==1){lib=openat(root_fd,"lib",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
   if(lib>=0&&!fstat(lib,&st)&&st.st_ino==49345&&st.st_uid==57285&&st.st_gid==1000&&(st.st_mode&07777)==0755&&major(st.st_dev)==252&&minor(st.st_dev)==15){
    memcpy(c.nonce,installation,16);memcpy(c.boot,r.boot_id,40);c.remount=remount_usr;c.readonly=ro;c.ready_process=live_im;gx_run(lib,dir,&c,&result);
   }}}
 r.reserved[0]=result.code;r.reserved[1]=result.reason;r.reserved[2]=result.journal_error;
 memcpy(r.tail,&result.restored,4);memcpy(r.tail+4,&result.ready,4);memcpy(r.tail+8,&result.readonly,4);memcpy(r.tail+12,&result.attempted_rename,4);
 if(result.code>GX_RESTORED||!result.readonly)r.status=1;
 int restart=result.code==GX_RESTORED&&result.restored&&result.readonly;
 if(restart&&no_snapshot_restart()){restart=0;r.status=2;}
 if(restart)r.flags|=128;
 im_observe(&r);r.mono_end_ns=mono();if(!r.mono_end_ns||r.mono_end_ns<r.mono_begin_ns)r.status=3;
 /* First result is retained across the following recovery reboot. The two
 * journal slots carry state for further boots; a completed proof is not overwritten. */
 int record_result=result.code==GX_STOCK?0:write_record(dir,&r);
 if(restart&&!r.status){sync();reboot(RB_AUTOBOOT);_exit(70);}
 if(result.code==GX_CONFIRMED&&result.ready&&result.readonly&&!r.status){
  struct gm_monitor monitor={0};
  if(!gm_arm(&monitor,dir,&c)){
   for(;;){uint32_t explicit_error=0;int mr=gm_poll(&monitor,dir,&c,&explicit_error);
    if(mr==1){
     c.force_recovery=1;struct gx_result recovered;gx_run(lib,dir,&c,&recovered);
     struct {uint32_t magic,bytes,error,monitor;struct gx_result result;} rr={0x38524741,sizeof rr,explicit_error,1,recovered};
     char name[64];snprintf(name,sizeof name,"runtime-%s.bin",c.boot);int f=openat(dir,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0400);
     if(f>=0){if(write(f,&rr,sizeof rr)==sizeof rr)fsync(f);close(f);fsync(dir);}
     if(recovered.code==GX_RESTORED&&recovered.restored&&recovered.readonly&&!no_snapshot_restart()){sync();reboot(RB_AUTOBOOT);_exit(71);}break;
    }
    /* Atomic publication means malformed .bin is not a writer-in-progress.
     * Keep observing without treating an unauthenticated record as permission
     * to recover. A later valid record can still trigger recovery. */
    struct timespec interval={1,0};while(nanosleep(&interval,&interval)&&errno==EINTR){}
   }
  }
 }
 if(lib>=0)close(lib);if(root_fd>=0)close(root_fd);
 close(lock);close(dir);_exit(record_result);
}
