#include "bundle.h"
extern long syscall(long,...);extern void*dlsym(void*,const char*);
struct dinfo{const char*path;void*base;const char*symbol;void*address;};extern int dladdr(const void*,struct dinfo*);
static int eq(const void*a,const void*b,unsigned n){const uint8_t*p=a,*q=b;unsigned d=0;while(n--)d|=*p++^*q++;return !d;}
static int number(const char*s,unsigned n,uint32_t*out){uint32_t v=0;if(!n)return -1;for(unsigned i=0;i<n;i++){if(s[i]<'0'||s[i]>'9'||v>(UINT32_MAX-(unsigned)(s[i]-'0'))/10)return -1;v=v*10+s[i]-'0';}*out=v;return v?0:-1;}
static void path(char*out,unsigned tid,const char*end){const char*p="/proc/self/task/";while(*p)*out++=*p++;char b[10];unsigned n=0;do{b[n++]=(char)('0'+tid%10);tid/=10;}while(tid);while(n)*out++=b[--n];while(*end)*out++=*end++;*out=0;}
static int read_file(const char*name,char*b,unsigned cap,unsigned*used){int fd=syscall(5,name,0x80000,0);if(fd<0)return -1;long n=syscall(3,fd,b,cap);int closed=syscall(6,fd);if(closed||n<=0||(unsigned)n>=cap)return -1;*used=n;b[n]=0;return 0;}
int fb_parse_stat(const char*b,unsigned n,unsigned tid,uint32_t*start){
 unsigned i=0;while(i<n&&b[i]!=' ')i++;uint32_t id;if(number(b,i,&id)||id!=tid||i+2>=n||b[i+1]!='(')return -1;
 unsigned end=n;while(end&&b[end-1]!=')')end--;if(!end||end+1>=n||b[end]!=' ')return -1;i=end+1;
 for(unsigned field=3;field<22;field++){unsigned begin=i;while(i<n&&b[i]!=' ')i++;if(i==begin||i==n)return -1;i++;}
 unsigned begin=i;while(i<n&&b[i]!=' '&&b[i]!='\n')i++;return number(b+begin,i-begin,start);
}
static int task(unsigned id,unsigned*start){char name[64],buf[1024];unsigned n;path(name,id,"/comm");if(read_file(name,buf,sizeof buf,&n)||n!=13||!eq(buf,"Appframework\n",13))return 1;
 path(name,id,"/stat");if(read_file(name,buf,sizeof buf,&n)||fb_parse_stat(buf,n,id,start))return -1;return 0;}
static int find(unsigned*id,unsigned*start){
 int fd=syscall(5,"/proc/self/task",0x84000,0);if(fd<0)return -1;unsigned found=0;int error=0;uint64_t aligned[512];uint8_t*b=(void*)aligned;
 for(unsigned call=0;call<64;call++){long n=syscall(217,fd,b,sizeof aligned);if(n<0||(unsigned)n>sizeof aligned){error=1;break;}if(!n)break;if(call==63){error=1;break;}
  for(unsigned off=0;off<(unsigned)n;){if((unsigned)n-off<20){error=1;break;}unsigned len=b[off+16]|((unsigned)b[off+17]<<8);if(len<20||len>(unsigned)n-off){error=1;break;}
   unsigned z=19;while(z<len&&b[off+z])z++;if(z==len){error=1;break;}uint32_t candidate;if(!number((char*)b+off+19,z-19,&candidate)){unsigned st;int rc=task(candidate,&st);if(rc<0){error=1;break;}if(!rc){found++;*id=candidate;*start=st;if(found>1){error=1;break;}}}off+=len;
  }if(error)break;
 }
 if(syscall(6,fd))error=1;return error?-1:found==1?0:1;
}
struct ui_anchor{uint32_t offset;uint8_t bytes[16];};
#include "ui_anchors.h"
int fb_ui_candidate(struct np_context*p,void*ref,uint32_t*tid,uint32_t*start,uint32_t*base,uint32_t*manager){
 if(!p||!ref||!tid||!start||!base||!manager||np_check(p))return -1;
 void*slot=dlsym(ref,"timerManager");struct dinfo d={0};if(!slot||!dladdr(slot,&d)||!d.base||(uint32_t)slot-(uint32_t)d.base!=0x12d4acc)return -1;*base=(uint32_t)d.base;
 uint8_t b[16];for(unsigned i=0;i<sizeof ui_anchors/sizeof ui_anchors[0];i++)if(np_read(p,*base+ui_anchors[i].offset,b,16)||!eq(b,ui_anchors[i].bytes,16))return -1;
 if(np_read(p,(uint32_t)slot,manager,4)||(*manager&3))return -1;if(!*manager)return 1;
 uint32_t words[10];if(np_read(p,*manager,words,sizeof words)||!np_range(&p->maps,*manager,sizeof words,NP_R|NP_W)||words[8]>1||words[9]!=p->s.pid||!np_range(&p->maps,words[0],4,NP_R)||(words[1]&&!np_range(&p->maps,words[1],24,NP_R)))return -1;
 unsigned id2=0,start2=0;int rc=find(tid,start);if(rc)return rc;
 if(find(&id2,&start2)||*tid!=id2||*start!=start2||*tid==p->s.pid||*tid==p->s.worker_tid)return -1;
 return np_check(p)?-1:0;
}
