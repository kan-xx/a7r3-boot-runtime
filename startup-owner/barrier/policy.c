#include "ports.h"
#include "../core/sha256_local.h"
static long sc(long n,long a,long b,long c,long d,long e,long f){register long r0 __asm__("r0")=a,r1 __asm__("r1")=b,r2 __asm__("r2")=c,r3 __asm__("r3")=d,r4 __asm__("r4")=e,r5 __asm__("r5")=f,r7 __asm__("r7")=n;__asm__ volatile("svc 0":"+r"(r0):"r"(r1),"r"(r2),"r"(r3),"r"(r4),"r"(r5),"r"(r7):"memory","cc");return r0;}
static int eq(const void*a,const void*b,unsigned z){const uint8_t*x=a,*y=b;uint8_t d=0;while(z--)d|=*x++^*y++;return !d;}
static uint32_t failed,allow_cold;void nb_cold_mode(unsigned x){allow_cold=!!x;}
/* Original ARM read_mem uses the existing kernel linear mapping (__va).
 * Do not create an O_SYNC/writecombine mmap alias for mutable RTOS RAM.
 * All requests remain within the known ARM reserved RAM (also preserving
 * the old lower bound), <=2048 bytes, and exact-length. No retry/cache op. */
static int phys(uint32_t a,void*out,unsigned bytes){
 if(failed||!out||!bytes||bytes>2048||a<0x03000000u||a>=0x048c6000u||bytes>0x048c6000u-a)return -1;
 long fd=sc(5,(long)"/dev/mem",0x80000,0,0,0,0);if(fd<0)return -1;
 /* ARM EABI pread64: r0=fd,r1=buffer,r2=count,r3=alignment padding,
  * r4=offset low,r5=offset high. Not the five-argument OABI layout. */
 long got=sc(180,fd,(long)out,bytes,0,a,0);
 long closed=sc(6,fd,0,0,0,0,0);
 if(closed)failed=1;
 return !closed&&got==(long)bytes?0:-1;
}
struct anchor{uint32_t address,bytes;uint8_t sha[32];};
#include "anchors.h"
int nb_anchors(struct bp_report*r){uint8_t b[2048],got[32];for(unsigned i=0;i<sizeof an/sizeof an[0];i++){if(an[i].bytes>sizeof b||phys(an[i].address,b,an[i].bytes))return -1;struct sha256 s;sha_init(&s);sha_add(&s,b,an[i].bytes);sha_end(&s,got);if(!eq(got,an[i].sha,32))return -1;r->anchors=i+1;}return 0;}
int nb_policy(uint32_t*notify){uint32_t a[3],e[40],e2[40],b[4];if(phys(0x041aaca4,notify,16)||phys(0x041a89c8,a,12)||phys(0x041aacc4,e,160)||phys(0x041aacc4,e2,160)||phys(0x041aaca4,b,16))return -1;
 int zero=!(notify[0]|notify[1]|notify[2]|notify[3]);return !((allow_cold&&zero)||((notify[0]&1)&&notify[1]==0x6467d1b0))||!(a[0]&1)||a[2]!=2||e[2]||e[0x50/4]||e[0x9c/4]||!eq(e,e2,160)||!eq(notify,b,16)?-1:0;}
void nb_delay(void){uint32_t t[2]={0,10000000};sc(162,(long)t,0,0,0,0,0);}
