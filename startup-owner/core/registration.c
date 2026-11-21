#include "registration.h"
#define GLOBAL_SEM 0x9401c3u
#define HEAD 0x14fccu
static void clear(void*p,unsigned n){uint8_t*b=p;while(n--)*b++=0;}
static int own(const struct rl_control*c){return c&&c->initialized&&c->cfg.port.tid(c->cfg.port.context)==c->cfg.worker_tid;}
static int fail(struct rl_control*c,uint32_t e){if(!c->status.error)c->status.error=e;return RL_ERROR;}
static int read_words(struct rl_control*c,uint32_t a,uint32_t*p,uint32_t n){
 if(!a||(a&3)||!n||n>11||a>UINT32_MAX-n*4)return fail(c,1);
 c->status.reads++;if(c->cfg.port.read(c->cfg.port.context,a,p,n))return fail(c,2);return 0;
}
static int unlock(struct rl_control*c,int result){
 struct rl_status*s=&c->status;int rc;
 if(s->node_held){rc=c->cfg.port.signal_sem(c->cfg.port.context,s->node_sem);s->last_rc=(uint32_t)rc;if(rc)result=fail(c,3);else s->node_held=0;}
 if(s->global_held){rc=c->cfg.port.signal_sem(c->cfg.port.context,GLOBAL_SEM);s->last_rc=(uint32_t)rc;if(rc)result=fail(c,4);else s->global_held=0;}
 return result;
}
static int lock_global(struct rl_control*c){
 int rc=c->cfg.port.try_sem(c->cfg.port.context,GLOBAL_SEM);c->status.last_rc=(uint32_t)rc;
 if(rc==-1022)return RL_BUSY;if(rc)return fail(c,5);c->status.global_held=1;return 0;
}
static int descriptor(struct rl_control*c){
 uint32_t d[11];if(c->cfg.port.find_entry(c->cfg.port.context,0xfffe,c->cfg.target_mask)!=c->cfg.descriptor)return fail(c,6);
 if(read_words(c,c->cfg.descriptor,d,11))return RL_ERROR;
 for(unsigned i=0;i<11;i++)if(d[i]!=c->cfg.descriptor_words[i])return fail(c,7);return 0;
}
static int node(struct rl_control*c,uint32_t*out,uint32_t words[8],int starting){
 uint32_t at,prev=0,found=0,found_words[8];if(read_words(c,HEAD,&at,1))return RL_ERROR;
 for(unsigned i=0;at;i++){
  uint32_t n[8];if(i==256)return fail(c,8);if(read_words(c,at,n,8))return RL_ERROR;
  if(n[1]!=prev)return fail(c,9);
  if(n[2]==c->cfg.descriptor){if(found)return fail(c,10);found=at;for(unsigned j=0;j<8;j++)found_words[j]=n[j];}
  prev=at;at=n[0];
 }
 if(!found)return fail(c,11);if(!found_words[7])return fail(c,12);
 /* Original b4e0 publishes handle only AFTER Init returns. The fresh worker
  * may run first; do not reject its valid, still-unpublished state1 node. */
 if(starting&&found_words[5]==1&&!found_words[4])return RL_BUSY;
 if(found_words[4]!=c->cfg.handle)return fail(c,12);
 *out=found;for(unsigned i=0;i<8;i++)words[i]=found_words[i];return 0;
}
static int refs(struct rl_control*c,uint32_t head,uint32_t*found,uint32_t*count){
 *found=*count=0;
 for(unsigned i=0;head;i++){
  uint32_t r[3];if(i==256)return fail(c,13);if(read_words(c,head,r,3))return RL_ERROR;
  if(!r[1]||r[1]>0x7fffffffu)return fail(c,14);
  if(r[2]==RL_MARKER){if(*found)return fail(c,15);*found=head;*count=r[1];}
  head=r[0];
 }return 0;
}
uint32_t rl_size(void){return sizeof(struct rl_control);}
int rl_init(struct rl_control*c,const struct rl_config*q){
 if(!c||c->initialized||!q||!q->port.tid||!q->port.read||!q->port.try_sem||!q->port.signal_sem||!q->port.find_entry||!q->port.add_reference||!q->pid||!q->worker_tid||q->pid==q->worker_tid||q->port.tid(q->port.context)!=q->worker_tid||!q->descriptor||!q->handle||q->target_mask!=1)return RL_ERROR;
 const uint32_t*d=q->descriptor_words;if(d[0]!=0x20000003||d[1]!=4||d[2]!=1||d[3]!=0xfffe)return RL_ERROR;for(unsigned i=4;i<11;i++)if(!d[i])return RL_ERROR;
 clear(c,sizeof*c);c->cfg=*q;c->status.abi=1;c->status.bytes=sizeof c->status;c->status.build=RL_BUILD;c->initialized=1;return 0;
}
int rl_acquire(struct rl_control*c){
 if(!own(c)||c->status.error)return RL_ERROR;if(c->status.owns_reference)return RL_ALREADY;if(c->status.attempted)return fail(c,16);
 int rc=lock_global(c);if(rc)return rc;uint32_t n[8],at=0,p=0,count=0;
 if(descriptor(c))return unlock(c,RL_ERROR);rc=node(c,&at,n,1);if(rc)return unlock(c,rc);
 /* Lifecycle state is written by the main thread without these semaphores.
  * All published live phases 2..6 may acquire a reference; requiring ACTIVE
  * would deadlock an early INACT waiting for this worker's completion. */
 if(n[5]==1)return unlock(c,RL_BUSY);if(n[5]<2||n[5]>6)return unlock(c,fail(c,17));
 c->status.node_sem=n[7];rc=c->cfg.port.try_sem(c->cfg.port.context,n[7]);c->status.last_rc=(uint32_t)rc;
 if(rc==-1022)return unlock(c,RL_BUSY);if(rc)return unlock(c,fail(c,18));c->status.node_held=1;
 if(refs(c,n[3],&p,&count))return unlock(c,RL_ERROR);if(p)return unlock(c,fail(c,19));
 /* Claim BEFORE canonical original ref insertion: an ambiguous outcome must
  * never cause a second counter increment on a later acquisition attempt. */
 c->status.attempted=1;c->status.add_calls++;rc=c->cfg.port.add_reference(c->cfg.port.context,c->cfg.descriptor,RL_MARKER);c->status.last_rc=(uint32_t)rc;
 uint32_t after[8];if(read_words(c,at,after,8)||refs(c,after[3],&p,&count))return unlock(c,RL_ERROR);
 c->status.node=at;c->status.reference=p;c->status.reference_count=count;c->status.owns_reference=p&&count==1;
 if(rc)return unlock(c,fail(c,20));if(!c->status.owns_reference||after[3]!=p)return unlock(c,fail(c,21));
 for(unsigned i=0;i<8;i++)if(i!=3&&i!=5&&after[i]!=n[i])return unlock(c,fail(c,22));
 if(after[5]<2||after[5]>6)return unlock(c,fail(c,22));
 uint32_t first[3];if(read_words(c,p,first,3))return unlock(c,RL_ERROR);if(first[0]!=n[3])return unlock(c,fail(c,23));
 return unlock(c,0);
}
int rl_snapshot(struct rl_control*c,uint32_t cmd,struct rl_state*out){
 if(!own(c)||!out||c->status.error||!c->status.owns_reference||(cmd!=0x940122&&cmd!=0x940123))return RL_ERROR;
 int rc=lock_global(c);if(rc)return rc;uint32_t at=0,n[8],p=0,count=0,pending;
 if(descriptor(c)||node(c,&at,n,0)||refs(c,n[3],&p,&count))return unlock(c,RL_ERROR);
 if(at!=c->status.node||n[7]!=c->status.node_sem||p!=c->status.reference||count!=1||n[5]<2||n[5]>6)return unlock(c,fail(c,24));
 if(read_words(c,cmd==0x940122?0x14fc4:0x14fc8,&pending,1))return unlock(c,RL_ERROR);if(pending>256)return unlock(c,fail(c,25));
 struct rl_state s={c->cfg.pid,c->cfg.descriptor,0xfffe,0x20000003,n[5],pending};rc=unlock(c,0);if(rc)return rc;*out=s;return 0;
}
int rl_report(const struct rl_control*c,struct rl_status*out){if(!own(c)||!out)return RL_ERROR;*out=c->status;return 0;}
