#include "cleanup_engine.h"
#include <string.h>
static int hex(const char*s,uint8_t out[32]){for(unsigned i=0;i<32;i++){unsigned v=0;for(unsigned j=0;j<2;j++){char c=s[2*i+j];unsigned n=c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:99;if(n>15)return 0;v=16*v+n;}out[i]=v;}return 1;}
int cl_same(const struct cl_identity*a,const struct cl_identity*b){return a->dev==b->dev&&a->ino==b->ino&&a->size==b->size&&a->mode==b->mode&&a->uid==b->uid&&a->gid==b->gid&&a->nlink==b->nlink&&a->mtime==b->mtime&&a->ctime==b->ctime&&a->mtime_ns==b->mtime_ns&&a->ctime_ns==b->ctime_ns&&!memcmp(a->sha,b->sha,32);}
static int candidate(const struct cl_identity*i,unsigned index){uint8_t sha[32];return index<CL_COUNT&&hex(cl_specs[index].sha,sha)&&i->dev==0xfc0f&&i->ino&&i->size==cl_specs[index].bytes&&i->mode==(0100000|cl_specs[index].mode)&&!i->uid&&!i->gid&&i->nlink==1&&!memcmp(i->sha,sha,32);}
static int take_close(const struct cl_api*a,int*f){int fd=*f;*f=-1;return fd<0?0:a->close_candidate(a->context,fd);}
int cl_run(const struct cl_api*a,int commit,struct cl_result*r){
 int fd[CL_COUNT];for(unsigned i=0;i<CL_COUNT;i++)fd[i]=-1;memset(r,0,sizeof*r);r->code=CL_INVALID;
 if(!a||!a->readonly||!a->qualify||!a->root_namespace||!a->remount||!a->open_candidate||!a->identify||!a->namespace_same||!a->references||!a->unlink_candidate||!a->absent||!a->sync_dirs||!a->close_candidate||(commit!=0&&commit!=1))return r->code;
 if(a->readonly(a->context)!=1)goto done;r->code=CL_QUALIFY;if(!a->qualify(a->context)||!a->root_namespace(a->context))goto done;
 r->code=CL_CANDIDATE;for(unsigned i=0;i<CL_COUNT;i++){fd[i]=a->open_candidate(a->context,i);if(fd[i]<0||a->identify(a->context,fd[i],r->identity+i)||!candidate(r->identity+i,i)||!a->namespace_same(a->context,i,fd[i],r->identity+i))goto done;}
 r->code=CL_DISTINCT;for(unsigned i=0;i<CL_COUNT;i++)for(unsigned k=0;k<i;k++)if(r->identity[i].dev!=r->identity[k].dev||r->identity[i].ino==r->identity[k].ino)goto done;
 r->code=CL_REFERENCED;if(a->references(a->context,r->identity,fd)!=0)goto done;
 r->verified=1;r->code=CL_OK;if(!commit)goto final_qualify;
 /* Qualification and reference checks are repeated immediately before RW.
  * Production remount independently repeats the EXACT f35 qualifier. */
 r->code=CL_QUALIFY;if(!a->qualify(a->context)||!a->root_namespace(a->context))goto done;
 r->code=CL_CHANGED;for(unsigned i=0;i<CL_COUNT;i++)if(!a->namespace_same(a->context,i,fd[i],r->identity+i))goto done;
 r->code=CL_REFERENCED;if(a->references(a->context,r->identity,fd)!=0)goto done;
 r->rw_attempted=1;r->code=CL_MOUNT;if(a->remount(a->context,0)||a->readonly(a->context)!=0)goto done;
 for(unsigned i=0;i<CL_COUNT;i++){
  r->code=CL_QUALIFY;if(!a->qualify(a->context)||!a->root_namespace(a->context))goto done;
  r->code=CL_CHANGED;for(unsigned j=i;j<CL_COUNT;j++)if(!a->namespace_same(a->context,j,fd[j],r->identity+j))goto done;
  r->code=CL_REFERENCED;if(a->references(a->context,r->identity,fd)!=0)goto done;
  r->code=CL_CHANGED;if(!a->namespace_same(a->context,i,fd[i],r->identity+i))goto done;
  r->code=CL_UNLINK;if(a->unlink_candidate(a->context,i))goto done;r->deleted|=1u<<i;
  /* No zero-link held inode may remain when requesting RO restoration.
   * A consumed close is NEVER retried even if its return is uncertain. */
  r->code=CL_CLOSE;if(take_close(a,fd+i)){r->close_uncertain|=1u<<i;goto done;}
  r->code=CL_SYNC;if(a->sync_dirs(a->context))goto done;
  r->code=CL_CHANGED;if(a->absent(a->context,i)!=1)goto done;
 }
 r->code=CL_OK;
final_qualify:
 if(!a->qualify(a->context)||!a->root_namespace(a->context))r->code=CL_QUALIFY;
done:
 for(unsigned i=0;i<CL_COUNT;i++)if(take_close(a,fd+i)){r->close_uncertain|=1u<<i;r->code=CL_CLOSE;}
 if(r->rw_attempted){if(a->sync_dirs(a->context)&&r->code==CL_OK)r->code=CL_SYNC;if(a->remount(a->context,1))r->code=CL_READONLY;}
 r->readonly=a->readonly(a->context)==1;if(r->rw_attempted&&!r->readonly)r->code=CL_READONLY;return r->code;
}
