#include "completion.h"
_Static_assert(sizeof(void*)==4,"Exact ARM32 ioctl ABI only");
static void clear(void*p,unsigned n){uint8_t*b=p;while(n--)*b++=0;}
static int fail(struct lc_control*c,uint32_t e){if(!c->status.error)c->status.error=e;return -1;}
static int own(const struct lc_control*c){return c&&c->initialized&&c->cfg.tid(c->cfg.context)==c->cfg.worker_tid;}
static int call(struct lc_control*c,uint32_t op,void*arg){
 if(*c->cfg.fd_slot!=c->borrowed_fd)return fail(c,1);
 c->status.ioctls++;int r=c->cfg.ioctl_one(c->cfg.context,c->borrowed_fd,op,arg);
 if(r==-1){int e=c->cfg.errno_value(c->cfg.context);r=(e>0&&e<=4095)?-e:-4095;}
 c->status.last_rc=(uint32_t)r;return r;
}
uint32_t lc_size(void){return sizeof(struct lc_control);}
int lc_init(struct lc_control*c,const struct lc_config*q){
 if(!c||c->initialized||!q||!q->tid||!q->ioctl_one||!q->errno_value||!q->fd_slot||!q->worker_tid||q->tid(q->context)!=q->worker_tid||*q->fd_slot<0||!q->pool_lo||q->pool_lo>=q->pool_hi||q->pool_hi-q->pool_lo<32||(q->pool_lo&3)||(q->pool_hi&3))return -1;
 clear(c,sizeof*c);c->cfg=*q;c->borrowed_fd=*q->fd_slot;c->status.abi=1;c->status.bytes=sizeof c->status;c->status.build=LC_BUILD;c->initialized=1;return 0;
}
int lc_complete(struct lc_control*c,uint32_t command,uint32_t id){
 if(!own(c)||id!=0xfffe||(command!=0x940122&&command!=0x940123))return -1;
 if(c->status.error||c->status.held_message)return -1;
 c->status.last_command=command;c->status.pointer_valid=0;
 uint32_t message=0,allocation[3]={(uint32_t)(uintptr_t)&message,16,0};
 uint32_t arg[2]={0x94016a,(uint32_t)(uintptr_t)allocation};
 /* The final zero is the original allocator's wait flag: never join its
  * memory wait list. A single libc ioctl avoids libosal's -1021 retry loop. */
 c->status.allocations++;int rc=call(c,0x8000000a,arg);
 c->status.held_message=message;c->status.held_destination=message?0x94016a:0;
 if(rc||!message)return fail(c,2);
 if((message&3)||message<c->cfg.pool_lo||message-c->cfg.pool_lo<12||message>c->cfg.pool_hi||c->cfg.pool_hi-message<16)return fail(c,3);
 c->status.pointer_valid=1;
 uint32_t*p=(uint32_t*)(uintptr_t)message;p[-1]=0x94016a;p[0]=command;p[1]=id;p[2]=p[3]=0;
 arg[1]=message;c->status.send_attempts++;rc=call(c,0x80000004,arg);
 /* Never replay or free on an uncertain handoff. Original caller freed on
  * error, but retaining is necessary when the syscall outcome is ambiguous. */
 if(rc)return fail(c,4);
 c->status.held_message=c->status.held_destination=0;c->status.notifications++;
 if(*c->cfg.fd_slot!=c->borrowed_fd)return fail(c,5);
 return 0;
}
int lc_report(const struct lc_control*c,struct lc_status*r){if(!own(c)||!r)return -1;*r=c->status;return 0;}
