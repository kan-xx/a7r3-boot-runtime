#include "ready_record.h"
#include "../platform/platform.h"
#include "../../boot-guard/transaction.h"
#include "sha256_local.h"
extern long syscall(long,...);
extern int *__errno_location(void);
static int ar_eq(const void*a,const void*b,unsigned n){const unsigned char*p=a,*q=b;unsigned d=0;while(n--)d|=*p++^*q++;return !d;}
static void ar_copy(void*a,const void*b,unsigned n){unsigned char*p=a;const unsigned char*q=b;while(n--)*p++=*q++;}
static int ar_fail(struct ar_ready_status*s,unsigned stage,int error){s->stage=stage;s->error=error>0?(unsigned)error:4095;return -1;}
static int ar_read(const char*path,void*out,unsigned cap){int f=syscall(5,path,AR_CLOEXEC|AR_NOFOLLOW,0);if(f<0)return -1;unsigned at=0;int good=1;for(unsigned i=0;i<1024&&at<cap;i++){long n=syscall(3,f,(char*)out+at,cap-at);if(n<0){good=0;break;}if(!n)break;at+=n;}char b;if(at==cap&&syscall(3,f,&b,1)!=0)good=0;if(syscall(6,f))good=0;return good?(int)at:-1;}
static int write_record(const char*path,const unsigned char*nonce,const unsigned char*hash,uint32_t build,uint32_t pid,uint32_t failure,struct ar_ready_status*s){
 if(!path||!nonce||!hash||!s||pid!=(uint32_t)syscall(20))return -1;*s=(struct ar_ready_status){0};
 int dir=syscall(5,path,AR_DIRECTORY|AR_NOFOLLOW|AR_CLOEXEC,0);if(dir<0)return ar_fail(s,1,*__errno_location());
 int rc=-1,f=-1;struct np_stat st;int err=0;unsigned stage=2;
 if(syscall(197,dir,&st)||st.mode!=0x41c0||st.uid||st.gid){err=22;goto done;}
 stage=3;unsigned char retired[16];int rf=syscall(322,dir,"retire.bin",AR_NOFOLLOW|AR_CLOEXEC,0);
 if(rf>=0){long n=syscall(3,rf,retired,16);int bad=n==16&&ar_eq(retired,nonce,16);if(syscall(6,rf)||bad){err=125;goto done;}}
 else if(*__errno_location()!=2){err=*__errno_location();goto done;}
 struct gx_record r={.abi=1,.bytes=256,.seq=1,.phase=failure?GX_FAILURE:GX_READY,.code=build,.pid=pid};ar_copy(r.magic,"A7GXST01",8);ar_copy(r.nonce,nonce,16);ar_copy(r.candidate,hash,32);
 stage=4;if(ar_read("/proc/sys/kernel/random/boot_id",r.boot,37)!=37||r.boot[36]!='\n'){err=22;goto done;}r.boot[36]=0;
 stage=5;char stat[1024];int n=ar_read("/proc/self/stat",stat,sizeof stat-1);if(n<1){err=22;goto done;}stat[n]=0;char*p=0;for(int i=0;i<n;i++)if(stat[i]==')')p=stat+i;if(!p||p[1]!=' '||!p[2]||p[3]!=' '){err=22;goto done;}p+=4;uint64_t start=0;
 for(unsigned field=4;field<=22;field++){if(!*p){err=22;goto done;}char*e=p;while(*e&&*e!=' ')e++;if(field==22){for(char*q=p;q<e;q++){if(*q<'0'||*q>'9'||start>(UINT64_MAX-9)/10){err=22;goto done;}start=start*10+*q-'0';}}p=*e?e+1:e;}
 if(!start){err=22;goto done;}ar_copy(r.extra,&start,8);if(failure)ar_copy(r.extra+8,&failure,4);
 char pending[49]="ready.new",final[49]="ready.bin";if(failure){ar_copy(pending,"failure-",8);ar_copy(pending+8,r.boot,36);ar_copy(pending+44,".new",5);ar_copy(final,"failure-",8);ar_copy(final+8,r.boot,36);ar_copy(final+44,".bin",5);}
 struct sha256 h;sha_init(&h);sha_add(&h,(void*)&r,224);sha_end(&h,r.digest);
 stage=6;f=syscall(322,dir,pending,AR_CREATE_EXCLUSIVE,0600);if(f<0){err=*__errno_location();goto done;}s->created=1;
 stage=7;if(syscall(197,f,&st)||st.mode!=0x8180||st.uid||st.gid||st.nlink!=1){err=22;goto done;}
 stage=8;if(syscall(4,f,&r,256)!=256||syscall(118,f)){err=*__errno_location();goto done;}
 stage=9;{int c=syscall(6,f);f=-1;if(c){err=*__errno_location();goto done;}}
 stage=10;if(syscall(329,dir,pending,dir,final)){err=*__errno_location();goto done;}s->renamed=1;
 stage=11;if(syscall(118,dir)){err=*__errno_location();goto done;}rc=0;
done:
 if(f>=0&&syscall(6,f)&&!err){err=*__errno_location();rc=-1;}if(syscall(6,dir)&&!err){err=*__errno_location();rc=-1;}
 if(rc)return ar_fail(s,stage,err);s->stage=12;return 0;
}

int ar_write_ready(const char*p,const unsigned char*n,const unsigned char*h,uint32_t b,uint32_t id,struct ar_ready_status*s){return write_record(p,n,h,b,id,0,s);}
int ar_write_failure(const char*p,const unsigned char*n,const unsigned char*h,uint32_t b,uint32_t id,uint32_t e,struct ar_ready_status*s){if(!e)return -1;return write_record(p,n,h,b,id,e,s);}

/* Forensics only: the guardian still uses the independently sealed 256-byte
 * failure record. This snapshot preserves the precise rejected substage. */
int ar_write_report(const char*path,const unsigned char*nonce,const unsigned char*hash,uint32_t build,uint32_t pid,const void*report,unsigned bytes,struct ar_ready_status*s){
 struct report_header {unsigned char magic[8];uint32_t abi,bytes,build,pid;unsigned char nonce[16],boot[40],candidate[32],digest[32],reserved[16];};
 _Static_assert(sizeof(struct report_header)==160,"report header ABI");
 if(!path||!nonce||!hash||!report||!s||bytes!=8192||pid!=(uint32_t)syscall(20))return -1;*s=(struct ar_ready_status){0};
 int dir=syscall(5,path,AR_DIRECTORY|AR_NOFOLLOW|AR_CLOEXEC,0);if(dir<0)return ar_fail(s,1,*__errno_location());
 int rc=-1,f=-1,err=0;unsigned stage=2;struct np_stat st;
 if(syscall(197,dir,&st)||st.mode!=0x41c0||st.uid||st.gid){err=22;goto done;}
 stage=3;unsigned char retired[16];int rf=syscall(322,dir,"retire.bin",AR_NOFOLLOW|AR_CLOEXEC,0);
 if(rf>=0){long n=syscall(3,rf,retired,16);int bad=n==16&&ar_eq(retired,nonce,16);if(syscall(6,rf)||bad){err=125;goto done;}}
 else if(*__errno_location()!=2){err=*__errno_location();goto done;}
 struct report_header h={.abi=1,.bytes=160+8192,.build=build,.pid=pid};ar_copy(h.magic,"A7RFULL2",8);ar_copy(h.nonce,nonce,16);ar_copy(h.candidate,hash,32);
 stage=4;if(ar_read("/proc/sys/kernel/random/boot_id",h.boot,37)!=37||h.boot[36]!='\n'){err=22;goto done;}h.boot[36]=0;
 struct sha256 digest;sha_init(&digest);sha_add(&digest,report,bytes);sha_end(&digest,h.digest);
 char pending[48],final[48];ar_copy(pending,"report-",7);ar_copy(pending+7,h.boot,36);ar_copy(pending+43,".new",5);ar_copy(final,"report-",7);ar_copy(final+7,h.boot,36);ar_copy(final+43,".bin",5);
 stage=6;f=syscall(322,dir,pending,AR_CREATE_EXCLUSIVE,0600);if(f<0){err=*__errno_location();goto done;}s->created=1;
 stage=7;if(syscall(197,f,&st)||st.mode!=0x8180||st.uid||st.gid||st.nlink!=1){err=22;goto done;}
 stage=8;if(syscall(4,f,&h,sizeof h)!=(long)sizeof h||syscall(4,f,report,bytes)!=(long)bytes||syscall(118,f)){err=*__errno_location();goto done;}
 stage=9;{int c=syscall(6,f);f=-1;if(c){err=*__errno_location();goto done;}}
 stage=10;if(syscall(329,dir,pending,dir,final)){err=*__errno_location();goto done;}s->renamed=1;
 stage=11;if(syscall(118,dir)){err=*__errno_location();goto done;}rc=0;
done:
 if(f>=0&&syscall(6,f)&&!err){err=*__errno_location();rc=-1;}if(syscall(6,dir)&&!err){err=*__errno_location();rc=-1;}
 if(rc)return ar_fail(s,stage,err);s->stage=12;return 0;
}
