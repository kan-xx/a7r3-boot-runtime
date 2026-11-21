#include "verify_file_hash.h"
#include "../core/sha256_local.h"

enum {BE_STATE=1,BE_CONFIG,BE_PORTS,BE_OPEN,BE_STAT,BE_IDENTITY,
      BE_READ,BE_EARLY_EOF,BE_TRAILING,BE_CHANGED,BE_DIGEST,BE_CLOSE,
      BE_CANCELLED,BE_OVERFLOW};
#define VF_MASK ((1u<<VF_FILES)-1u)
#define VF_IO_BYTES 4096u
#define VF_READS_MAX (VF_CHUNK_MAX/VF_IO_BYTES)
_Static_assert(sizeof(struct sha256)<=sizeof(union vf_sha_storage),"SHA state fits opaque storage");

static void zero(void*out,unsigned n){uint8_t*p=out;while(n--)*p++=0;}
static void copy(void*out,const void*in,unsigned n){uint8_t*p=out;const uint8_t*q=in;while(n--)*p++=*q++;}
static int ports_ok(const struct vf_ports*p,int body){return p&&p->open&&p->stat&&p->close&&(!body||p->read);}
static int close_once(struct vf_state*s,const struct vf_ports*p){
 int fd=s->fd;s->fd=-1;
 if(fd>=0&&(!p||!p->close||p->close(p->context,fd))){s->close_uncertain=1;return 0;}
 return !s->close_uncertain;
}
static int failed(struct vf_state*s,const struct vf_ports*p,unsigned error){
 if(!s->error)s->error=error;s->active=0;
 if(!close_once(s,p)&&!s->error)s->error=BE_CLOSE;
 return VF_FAILED;
}
static int configs_ok(const struct vf_config*c){
 if(!c)return 0;uint64_t total=0;
 for(unsigned i=0;i<VF_FILES;i++){
  if(!c[i].path||!c[i].path[0]||(c[i].mode&~07777u)||(c[i].flags&~VF_ROOT_ONLY))return 0;
  total+=c[i].bytes;
 }
 return total<=UINT32_MAX;
}
static int expected(const struct vf_identity*i,const struct vf_config*c){
 return i->dev==0xfc0fu&&i->size==(int64_t)c->bytes&&i->nlink==1&&
        (i->mode&0170000u)==0100000u&&(!c->mode||(i->mode&07777u)==c->mode)&&
        (!(c->flags&VF_ROOT_ONLY)||(!i->uid&&!i->gid));
}
int vf_identity_equal(const struct vf_identity*a,const struct vf_identity*b){
 return a&&b&&a->dev==b->dev&&a->inode==b->inode&&a->size==b->size&&
        a->mode==b->mode&&a->nlink==b->nlink&&a->uid==b->uid&&a->gid==b->gid&&
        a->mtime==b->mtime&&a->mtimens==b->mtimens&&a->ctime==b->ctime&&a->ctimens==b->ctimens;
}
int vf_init(struct vf_state*s){
 if(!s)return VF_FAILED;
 /* Fresh callers zero-initialize. A live/uncertain descriptor cannot be erased. */
 if(s->abi==1&&(s->fd>=0||s->close_uncertain))return VF_FAILED;
 zero(s,sizeof*s);s->abi=1;s->active=1;s->fd=-1;return VF_MORE;
}
int vf_cancel(struct vf_state*s,const struct vf_ports*p){
 if(!s||s->abi!=1)return VF_FAILED;
 s->active=0;s->last_bytes=0;if(!s->error)s->error=BE_CANCELLED;
 return close_once(s,p)?VF_DONE:VF_FAILED;
}
int vf_step(struct vf_state*s,const struct vf_config c[VF_FILES],const struct vf_ports*p){
 if(!s||s->abi!=1)return VF_FAILED;
 s->last_bytes=0;
 if(s->error||s->close_uncertain)return failed(s,p,s->error?s->error:BE_CLOSE);
 if(s->index==VF_FILES&&s->verified_mask==VF_MASK&&!s->active&&s->fd<0)return VF_DONE;
 if(!s->active||s->index>=VF_FILES)return failed(s,p,BE_STATE);
 if(s->verified_mask!=((1u<<s->index)-1u))return failed(s,p,BE_STATE);
 if(!configs_ok(c))return failed(s,p,BE_CONFIG);
 if(!ports_ok(p,1))return failed(s,p,BE_PORTS);
 if(s->steps==UINT32_MAX)return failed(s,p,BE_OVERFLOW);s->steps++;
 const struct vf_config*cfg=c+s->index;struct sha256 sha;
 uint64_t progress=s->file_done;for(unsigned i=0;i<s->index;i++)progress+=c[i].bytes;
 if(progress!=s->total_bytes)return failed(s,p,BE_STATE);
 if(s->fd<0){
  if(s->file_done)return failed(s,p,BE_STATE);
  int fd=p->open(p->context,cfg->path);if(fd<0)return failed(s,p,BE_OPEN);s->fd=fd;
  if(p->stat(p->context,fd,&s->before))return failed(s,p,BE_STAT);
  if(!expected(&s->before,cfg))return failed(s,p,BE_IDENTITY);
  zero(&sha,sizeof sha);sha_init(&sha);copy(s->sha.bytes,&sha,sizeof sha);
 }
 if(s->file_done>cfg->bytes)return failed(s,p,BE_STATE);
 if(!expected(&s->before,cfg))return failed(s,p,BE_STATE);
 copy(&sha,s->sha.bytes,sizeof sha);
 if(sha.n!=s->file_done||sha.used>=64||sha.used!=(s->file_done&63u))return failed(s,p,BE_STATE);
 uint8_t buffer[VF_IO_BYTES];unsigned reads=0;
 while(s->file_done<cfg->bytes&&s->last_bytes<VF_CHUNK_MAX&&reads<VF_READS_MAX){
  uint32_t n=cfg->bytes-s->file_done;if(n>sizeof buffer)n=sizeof buffer;
  if(n>VF_CHUNK_MAX-s->last_bytes)n=VF_CHUNK_MAX-s->last_bytes;
  int got=p->read(p->context,s->fd,buffer,n);reads++;
  if(got<0||(uint32_t)got>n)return failed(s,p,BE_READ);
  if(!got)return failed(s,p,BE_EARLY_EOF);
  if(UINT32_MAX-s->total_bytes<(uint32_t)got)return failed(s,p,BE_OVERFLOW);
  sha_add(&sha,buffer,(unsigned)got);s->file_done+=(uint32_t)got;
  s->total_bytes+=(uint32_t)got;s->last_bytes+=(uint32_t)got;
 }
 copy(s->sha.bytes,&sha,sizeof sha);
 if(s->file_done<cfg->bytes||s->last_bytes==VF_CHUNK_MAX||reads==VF_READS_MAX)return VF_MORE;
 /* EOF consumes a requested byte of remaining budget; never exceed48KiB even
  * if a supposedly exact-size regular file unexpectedly grew. */
 int got=p->read(p->context,s->fd,buffer,1);
 if(got<0||got>1)return failed(s,p,BE_READ);
 if(got){s->last_bytes++;if(s->total_bytes!=UINT32_MAX)s->total_bytes++;return failed(s,p,BE_TRAILING);}
 struct vf_identity after;
 if(p->stat(p->context,s->fd,&after))return failed(s,p,BE_STAT);
 if(!vf_identity_equal(&s->before,&after))return failed(s,p,BE_CHANGED);
 uint8_t digest[32];sha_end(&sha,digest);unsigned diff=0;
 for(unsigned i=0;i<32;i++)diff|=digest[i]^cfg->sha256[i];
 if(diff)return failed(s,p,BE_DIGEST);
 if(!close_once(s,p))return failed(s,p,BE_CLOSE);
 s->snapshot[s->index]=s->before;s->verified_mask|=1u<<s->index;s->index++;s->file_done=0;
 if(s->index==VF_FILES){s->active=0;return VF_DONE;}
 return VF_MORE;
}
int vf_revalidate(struct vf_state*s,const struct vf_config c[VF_FILES],const struct vf_ports*p){
 if(!s||s->abi!=1)return VF_FAILED;s->last_bytes=0;
 if(s->error||s->close_uncertain)return failed(s,p,s->error?s->error:BE_CLOSE);
 if(s->active||s->index!=VF_FILES||s->verified_mask!=VF_MASK||s->fd>=0)return failed(s,p,BE_STATE);
 if(!configs_ok(c))return failed(s,p,BE_CONFIG);
 if(!ports_ok(p,0))return failed(s,p,BE_PORTS);
 for(unsigned i=0;i<VF_FILES;i++){
  int fd=p->open(p->context,c[i].path);if(fd<0)return failed(s,p,BE_OPEN);s->fd=fd;
  struct vf_identity current;
  if(p->stat(p->context,fd,&current))return failed(s,p,BE_STAT);
  if(!expected(&current,c+i)||!vf_identity_equal(&current,s->snapshot+i))return failed(s,p,BE_CHANGED);
  if(!close_once(s,p))return failed(s,p,BE_CLOSE);
 }
 return VF_DONE;
}
