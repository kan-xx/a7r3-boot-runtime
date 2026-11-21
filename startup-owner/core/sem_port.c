#include "sem_port.h"
static int reject(struct sp_control*c){c->status.rejections++;c->status.last_rc=SP_REJECT;return SP_REJECT;}
static int allowed(struct sp_control*c,uint32_t s){return (s&0xffff8000u)==0x940000u&&(s==SP_GLOBAL||(s!=SP_GLOBAL&&s==c->port.node(c->port.ctx)));}
void sp_init(struct sp_control*c,const struct sp_port*p){*c=(struct sp_control){.port=*p,.status={.abi=1,.bytes=sizeof(struct sp_status)}};}
int sp_acquire(struct sp_control*c,uint32_t s){
 c->status.acquire_calls++;if(!allowed(c,s)||c->port.check(c->port.ctx))return reject(c);
 uint32_t*owned=s==SP_GLOBAL?&c->status.global_owned:&c->status.node_owned;
 uint32_t*attempted=s==SP_GLOBAL?&c->status.global_attempted:&c->status.node_attempted;
 if(*owned)return reject(c);
 /* Node acquisition is only legal within this worker's global transaction. */
 if(s!=SP_GLOBAL&&(!c->status.global_owned||!c->port.held(c->port.ctx,SP_GLOBAL)))return reject(c);
 c->status.ioctls++;int r=c->port.invoke(c->port.ctx,0x80000001u,s);c->status.last_rc=r;
 if(!r){*owned=1;*attempted=0;if(s!=SP_GLOBAL)c->status.node_id=s;}return r;
}
int sp_release(struct sp_control*c,uint32_t s){
 c->status.release_calls++;if(!allowed(c,s))return reject(c);
 uint32_t*owned=s==SP_GLOBAL?&c->status.global_owned:&c->status.node_owned;
 uint32_t*attempted=s==SP_GLOBAL?&c->status.global_attempted:&c->status.node_attempted;
 if(!*owned||*attempted||!c->port.held(c->port.ctx,s)||(s!=SP_GLOBAL&&s!=c->status.node_id)||c->port.release_check(c->port.ctx))return reject(c);
 /* Mark before syscall: an ambiguous return must never trigger a retry. */
 *attempted=1;c->status.ioctls++;int r=c->port.invoke(c->port.ctx,0x80000002u,s);c->status.last_rc=r;
 if(!r)*owned=0;return r;
}
