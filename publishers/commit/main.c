/* Fixed manifest wrapper; the tested core retains the mapped old inode. */
#define _GNU_SOURCE
#include "install.c"
#include "production_identity.h"
#include "../../boot-guard/configuration.h"
#include <sys/statfs.h>
#include <sys/mount.h>
#include <sys/sysmacros.h>
static int root=-1;
static int readonly(void*x){(void)x;struct stat s;struct statfs f;if(root<0||fstat(root,&s)||!S_ISDIR(s.st_mode)||s.st_uid||major(s.st_dev)!=252||minor(s.st_dev)!=15||fstatfs(root,&f)||f.f_type!=0xef53)return -1;return !!(f.f_flags&MS_RDONLY);}
static int remount(void*x,int ro){(void)x;if(readonly(0)<0)return -1;return mount(NULL,"/usr",NULL,MS_REMOUNT|MS_RELATIME|(ro?MS_RDONLY:0),NULL);}
static int check_file(const struct payload*p){int f=open(p->path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);struct identity x;int good=f>=0&&!identify(f,&x)&&x.s.st_nlink==1&&x.s.st_size==(off_t)p->bytes&&!memcmp(x.hash,p->hash,32)&&x.s.st_uid==p->uid&&x.s.st_gid==p->gid&&x.s.st_mode==(S_IFREG|p->mode);if(f>=0&&close(f))good=0;return good;}
int main(int argc,char**argv){setbuf(stdout,NULL);int commit=argc==2&&!strcmp(argv[1],"--commit");if(argc!=2||(!commit&&strcmp(argv[1],"--verify"))||geteuid())return 90;
 struct gi_result r={.code=GI_INVALID};int lib=-1;struct stat st;
 root=open("/usr",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(readonly(0)!=1)goto done;
 lib=openat(root,"lib",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(lib<0||fstat(lib,&st)||!S_ISDIR(st.st_mode)||st.st_uid!=57285||st.st_gid!=1000||(st.st_mode&07777)!=0755||major(st.st_dev)!=252||minor(st.st_dev)!=15)goto done;
 for(unsigned i=0;i<sizeof payloads/sizeof payloads[0];i++)if(!check_file(payloads+i)){r.code=80+i;goto done;}
 struct gx_config c=configuration;c.remount=remount;c.readonly=readonly;gi_run(lib,&c,SOURCE_NAME,RETAINED_ORIGINAL,commit,&r);
done:if(lib>=0&&close(lib))r.code=GI_CLOSE;if(root>=0){r.readonly=readonly(0)==1;if(close(root))r.code=GI_CLOSE;}
 printf("GI_COMMIT mode=%s code=%u verified=%u linked=%u renamed=%u readonly=%u\n",commit?"commit":"verify",r.code,r.verified,r.linked,r.renamed,r.readonly);return r.code;}
