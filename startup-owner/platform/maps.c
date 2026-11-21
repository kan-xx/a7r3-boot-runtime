#include "platform.h"
static int same(const char*a,const char*b){while(*a&&*a==*b){a++;b++;}return *a==*b;}
static int number(const char**p,unsigned base,uint64_t max,uint64_t*out){uint64_t n=0;unsigned digits=0;for(;;){unsigned char c=(unsigned char)**p;unsigned d=c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:16;if(d>=base)break;if(n>(max-d)/base)return 0;n=n*base+d;(*p)++;digits++;}*out=n;return digits!=0;}
static int space(const char**p){if(**p!=' ')return 0;while(**p==' ')(*p)++;return 1;}
int np_parse_map(const char*p,struct np_map*m){
 uint64_t a,b,o,ma,mi,ino;if(!number(&p,16,0xffffffffu,&a)||*p++!='-'||!number(&p,16,0xffffffffu,&b)||a>=b||!space(&p))return 0;
 uint32_t f=0;if(*p=='r')f|=NP_R;else if(*p!='-')return 0;p++;
 if(*p=='w')f|=NP_W;else if(*p!='-')return 0;p++;
 if(*p=='x')f|=NP_X;else if(*p!='-')return 0;p++;
 if(*p=='s')f|=NP_SHARED;else if(*p!='p')return 0;p++;
 if(!space(&p)||!number(&p,16,0xffffffffu,&o)||!space(&p)||!number(&p,16,0xffffffffu,&ma)||*p++!=':'||!number(&p,16,0xffffffffu,&mi)||!space(&p)||!number(&p,10,UINT64_MAX,&ino))return 0;
 if(*p&&!space(&p))return 0;
 m->lo=a;m->hi=b;m->offset=o;m->flags=f;m->major=ma;m->minor=mi;m->inode=ino;
 m->kind=same(p,"/usr/bin/im.elf")?NP_IM:same(p,"/usr/lib/libosal_uipc.so")?NP_OSAL:same(p,"/lib/libc-2.11.2.so")?NP_LIBC:same(p,"/dev/uipc")?NP_UIPC:NP_OTHER;
 return 1;
}
int np_range(const struct np_maps*m,uint32_t a,uint32_t n,uint32_t f){
 if(!m||!n||a>UINT32_MAX-n||m->count>NP_MAX_MAPS)return 0;
 uint32_t end=a+n;for(uint32_t i=0;i<m->count;i++){const struct np_map*r=m->rows+i;if(r->hi<=a)continue;if(r->lo>a||(r->flags&f)!=f)return 0;if(r->hi>=end)return 1;a=r->hi;}return 0;
}
