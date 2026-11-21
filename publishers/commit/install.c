/* Shared exact inode/hash helpers, compiled once. No generic paths accepted by
 * the eventual production main; that wrapper supplies the fixed manifest. */
#include "../../boot-guard/transaction.c"
#include "install.h"
int gi_run(int dir,const struct gx_config*c,const char*source,const char*retained,int commit,struct gi_result*out){
 memset(out,0,sizeof*out);out->code=GI_INVALID;int old=-1,stock=-1,next=-1,rw_attempted=0;struct identity a,b,n;struct stat st;
 if(!c||!c->remount||!c->readonly||!basename_ok(c->target)||!basename_ok(c->standby)||!basename_ok(source)||!basename_ok(retained)||(commit!=0&&commit!=1)||!strcmp(c->target,c->standby)||!strcmp(c->target,source)||!strcmp(c->target,retained)||!strcmp(c->standby,source)||!strcmp(c->standby,retained)||!strcmp(source,retained)||c->readonly(c->context)!=1)goto done;
 if(fstat(dir,&st)||!S_ISDIR(st.st_mode))goto done;
 if(!fstatat(dir,retained,&st,AT_SYMLINK_NOFOLLOW)||errno!=ENOENT)goto done;
 out->code=GI_SOURCE;old=openat(dir,c->target,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);stock=openat(dir,c->standby,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);next=openat(dir,source,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
 if(old<0||stock<0||next<0||identify(old,&a)||identify(stock,&b)||identify(next,&n)||!matches(&a,c,1)||!matches(&b,c,1)||!matches(&n,c,0)||a.s.st_nlink!=1||b.s.st_nlink!=1||n.s.st_nlink!=1||a.s.st_dev!=b.s.st_dev||a.s.st_dev!=n.s.st_dev||a.s.st_ino==b.s.st_ino||a.s.st_ino==n.s.st_ino||b.s.st_ino==n.s.st_ino)goto done;
 out->verified=1;if(!commit){out->code=GI_OK;goto done;}
 out->code=GI_MOUNT;rw_attempted=1;if(c->remount(c->context,0)||c->readonly(c->context)!=0)goto done;
 out->code=GI_SYNC;if(fsync(stock)||fsync(next)||fsync(dir))goto done;
 out->code=GI_CHANGED;if(!unchanged(dir,c->target,old,&a)||!unchanged(dir,c->standby,stock,&b)||!unchanged(dir,source,next,&n))goto done;
 /* Keep the *currently mapped original inode* reachable. The standby is a
  * different inode; it cannot prevent Sony fs_may_remount_ro rejecting the
  * zero-link old inode after rename. Never delete this alias in this process. */
 out->code=GI_LINK;if(linkat(dir,c->target,dir,retained,0))goto done;out->linked=1;a.s.st_nlink=2;
 out->code=GI_CHANGED;if(!unchanged(dir,c->target,old,&a)||!unchanged(dir,retained,old,&a))goto done;
 out->code=GI_SYNC;if(fsync(dir))goto done;
 out->code=GI_CHANGED;if(!unchanged(dir,source,next,&n)||!unchanged(dir,c->standby,stock,&b))goto done;
 out->code=GI_RENAME;if(renameat(dir,source,dir,c->target))goto done;out->renamed=1;a.s.st_nlink=1;
 out->code=GI_CHANGED;if(!unchanged(dir,retained,old,&a)||!unchanged(dir,c->target,next,&n)||!unchanged(dir,c->standby,stock,&b))goto done;
 out->code=GI_SYNC;if(fsync(dir))goto done;out->code=GI_OK;
done:
 if(rw_attempted&&c->remount(c->context,1))out->code=GI_READONLY;
 if(c&&c->readonly)out->readonly=c->readonly(c->context)==1;
 if(rw_attempted&&!out->readonly)out->code=GI_READONLY;
 if(old>=0&&close(old))out->code=GI_CLOSE;if(stock>=0&&close(stock))out->code=GI_CLOSE;if(next>=0&&close(next))out->code=GI_CLOSE;
 return out->code;
}
