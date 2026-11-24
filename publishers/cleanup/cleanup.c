#include "qualification_prefix.inc"
#include "cleanup_engine.h"
#include <dirent.h>
#include <inttypes.h>
static struct stat pinned_usr,pinned_lib;
static unsigned scan_pids,scan_lines,scan_fds,scan_bytes,reference_pid,reference_kind;
static int decimal_name(const char*s){if(!*s)return 0;for(unsigned i=0;s[i];i++)if(s[i]<'0'||s[i]>'9'||i>=10)return 0;return 1;}
static int referenced(const struct cl_identity ids[CL_COUNT],dev_t dev,ino_t ino){for(unsigned i=0;i<CL_COUNT;i++)if(ids[i].dev==(uint64_t)dev&&ids[i].ino==(uint64_t)ino)return 1;return 0;}
static int parse_map(const char*line,const struct cl_identity ids[CL_COUNT]){
 unsigned long long lo,hi,off,ino;unsigned ma,mi;char perm[8];int used=0;
 if(sscanf(line,"%llx-%llx %7s %llx %x:%x %llu %n",&lo,&hi,perm,&off,&ma,&mi,&ino,&used)!=7||!used||lo>=hi||ma>0xfff||mi>0xfffff)return -1;
 return referenced(ids,makedev(ma,mi),(ino_t)ino);
}
static int is_held(int f,const int held[CL_COUNT]){for(unsigned i=0;i<CL_COUNT;i++)if(f==held[i])return 1;return 0;}
static int scan_references(void*x,const struct cl_identity ids[CL_COUNT],const int held[CL_COUNT]){
 (void)x;scan_pids=scan_lines=scan_fds=scan_bytes=reference_pid=reference_kind=0;DIR*proc=opendir("/proc");if(!proc)return -1;int result=0;struct dirent*de;errno=0;
 while((errno=0,(de=readdir(proc)))){if(!decimal_name(de->d_name))continue;if(++scan_pids>4096){result=-1;break;}unsigned pid=(unsigned)strtoul(de->d_name,0,10);int pd=openat(dirfd(proc),de->d_name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(pd<0){if(errno==ENOENT||errno==ESRCH)continue;result=-1;break;}
  int mf=openat(pd,"maps",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(mf<0){int gone=errno==ENOENT||errno==ESRCH;close(pd);if(gone)continue;result=-1;break;}FILE*m=fdopen(mf,"r");if(!m){close(mf);close(pd);result=-1;break;}char line[2048];unsigned lines=0;
  while(fgets(line,sizeof line,m)){size_t n=strlen(line);if(!n||line[n-1]!='\n'||++lines>8192||++scan_lines>131072||(scan_bytes+=(unsigned)n)>32u*1024*1024){result=-1;break;}int hit=parse_map(line,ids);if(hit){result=hit<0?-1:1;reference_pid=pid;reference_kind=1;break;}}
  int map_error=ferror(m);if(fclose(m))map_error=1;if(map_error)result=-1;if(result){close(pd);break;}
  int ff=openat(pd,"fd",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(ff<0){int gone=errno==ENOENT||errno==ESRCH;close(pd);if(gone)continue;result=-1;break;}DIR*fds=fdopendir(ff);if(!fds){close(ff);close(pd);result=-1;break;}struct dirent*fe;unsigned count=0;
  while((errno=0,(fe=readdir(fds)))){if(!decimal_name(fe->d_name))continue;if(++count>8192||++scan_fds>131072){result=-1;break;}struct stat st;if(fstatat(dirfd(fds),fe->d_name,&st,0)){if(errno==ENOENT||errno==ESRCH)continue;result=-1;break;}if(!referenced(ids,st.st_dev,st.st_ino))continue;int f=(int)strtoul(fe->d_name,0,10);if(pid==(unsigned)getpid()&&is_held(f,held))continue;result=1;reference_pid=pid;reference_kind=2;break;}
  if(!fe&&errno)result=-1;if(closedir(fds))result=-1;if(close(pd))result=-1;if(result)break;errno=0;
 }
 if(!de&&errno)result=-1;if(closedir(proc))result=-1;return result;
}
static int stat_same(const struct stat*a,const struct stat*b){return a->st_dev==b->st_dev&&a->st_ino==b->st_ino&&a->st_size==b->st_size&&a->st_mode==b->st_mode&&a->st_uid==b->st_uid&&a->st_gid==b->st_gid&&a->st_nlink==b->st_nlink&&a->st_mtim.tv_sec==b->st_mtim.tv_sec&&a->st_mtim.tv_nsec==b->st_mtim.tv_nsec&&a->st_ctim.tv_sec==b->st_ctim.tv_sec&&a->st_ctim.tv_nsec==b->st_ctim.tv_nsec;}
static int ci(void*x,int fd,struct cl_identity*out){(void)x;struct identity a;struct stat b;if(identify(fd,&a)||fstat(fd,&b)||!stat_same(&a.s,&b))return -1;*out=(struct cl_identity){.dev=a.s.st_dev,.ino=a.s.st_ino,.size=a.s.st_size,.mode=a.s.st_mode,.uid=a.s.st_uid,.gid=a.s.st_gid,.nlink=a.s.st_nlink,.mtime=a.s.st_mtim.tv_sec,.ctime=a.s.st_ctim.tv_sec,.mtime_ns=a.s.st_mtim.tv_nsec,.ctime_ns=a.s.st_ctim.tv_nsec};memcpy(out->sha,a.hash,32);return 0;}
static int cq(void*x){return qualify(x);}
static int root_namespace(void*x){(void)x;int u=open("/usr",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC),l=open("/usr/lib",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);struct stat a,b;int good=u>=0&&l>=0&&!fstat(u,&a)&&!fstat(l,&b)&&a.st_dev==pinned_usr.st_dev&&a.st_ino==pinned_usr.st_ino&&b.st_dev==pinned_lib.st_dev&&b.st_ino==pinned_lib.st_ino;if(u>=0&&close(u))good=0;if(l>=0&&close(l))good=0;return good;}
static int co(void*x,unsigned i){(void)x;return i<CL_COUNT?openat(lib,cl_names[i],O_RDONLY|O_NOFOLLOW|O_CLOEXEC):-1;}
static int cn(void*x,unsigned i,int held,const struct cl_identity*expected){if(i>=CL_COUNT||!expected||(cl_expected_inodes[i]&&expected->ino!=cl_expected_inodes[i]))return 0;struct cl_identity a,b;int good=i<CL_COUNT&&!ci(x,held,&a)&&cl_same(&a,expected),f=co(x,i);if(f<0)return 0;if(ci(x,f,&b)||!cl_same(&b,expected))good=0;if(close(f))good=0;return good;}
static int cm(void*x,int readonly){int rc=remount(x,readonly);/* RO restoration must not depend on requalification; this fallback can only make the fixed filesystem READONLY. */if(readonly&&rc)rc=mount(0,"/usr",0,MS_REMOUNT|MS_RELATIME|MS_RDONLY,0);return rc;}
static int cu(void*x,unsigned i){(void)x;return i<CL_COUNT?unlinkat(lib,cl_names[i],0):-1;}
static int ca(void*x,unsigned i){(void)x;struct stat s;if(i>=CL_COUNT||!fstatat(lib,cl_names[i],&s,AT_SYMLINK_NOFOLLOW))return 0;return errno==ENOENT;}
static int cs(void*x){(void)x;int a=fsync(lib),b=fsync(usr);return a||b?-1:0;}
static int cc(void*x,int fd){(void)x;return close(fd);}
static void space(const char*when){struct statfs f;if(usr<0||fstatfs(usr,&f)){printf("OBSOLETE_CLEAN_SPACE when=%s unknown=1\n",when);return;}printf("OBSOLETE_CLEAN_SPACE when=%s bsize=%lu bfree=%lu bavail=%lu free_bytes=%"PRIu64"\n",when,(unsigned long)f.f_bsize,(unsigned long)f.f_bfree,(unsigned long)f.f_bavail,(uint64_t)f.f_bsize*f.f_bfree);}
int main(int argc,char**argv){setbuf(stdout,0);if(argc!=5||(!strcmp(argv[1],"--verify")?0:strcmp(argv[1],"--commit"))||!uuid(argv[2]))return 90;struct epoch e={0};memcpy(e.boot,argv[2],36);char*end=0;errno=0;unsigned long p=strtoul(argv[3],&end,10);if(errno||!end||*end||p<2||p>INT_MAX)return 91;e.pid=p;errno=0;e.start=strtoull(argv[4],&end,10);if(errno||!end||*end||!e.start||argv[4][0]=='-')return 91;
 if((CL_BOOT[0]&&strcmp(e.boot,CL_BOOT))||(CL_PID&&e.pid!=CL_PID)||(CL_START&&e.start!=CL_START))return 93;
 usr=open("/usr",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);lib=open("/usr/lib",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);journal=open("/tmp/a7r3-startup-full-v14",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);space("before");struct cl_result r={.code=92};int commit=!strcmp(argv[1],"--commit");if(usr>=0&&lib>=0&&journal>=0&&!fstat(usr,&pinned_usr)&&!fstat(lib,&pinned_lib)){struct cl_api a={&e,ro,cq,root_namespace,cm,co,ci,cn,scan_references,cu,ca,cs,cc};cl_run(&a,commit,&r);}space("after");
 for(unsigned i=0;i<CL_COUNT;i++)printf("OBSOLETE_CLEAN_FILE name=%s dev=%"PRIu64" ino=%"PRIu64" bytes=%"PRIu64" nlink=%u expected_sha=%s\n",cl_names[i],r.identity[i].dev,r.identity[i].ino,r.identity[i].size,r.identity[i].nlink,cl_specs[i].sha);
 if(journal>=0&&close(journal)&&!r.code)r.code=CL_CLOSE;if(lib>=0&&close(lib)&&!r.code)r.code=CL_CLOSE;if(usr>=0&&close(usr)&&!r.code)r.code=CL_CLOSE;printf("OBSOLETE_CLEAN mode=%s code=%u verified=%u deleted_mask=%u readonly=%u rw_attempted=%u close_uncertain=%u qualification=%u pids=%u maplines=%u fdchecks=%u reference_pid=%u reference_kind=%u archive_check=not_performed_requires_root_host_archive\n",commit?"commit":"verify",r.code,r.verified,r.deleted,r.readonly,r.rw_attempted,r.close_uncertain,qualification_stage,scan_pids,scan_lines,scan_fds,reference_pid,reference_kind);return r.code;}
