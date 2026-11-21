#ifndef A7_TOUCH_VERIFY_FILE_HASH_H
#define A7_TOUCH_VERIFY_FILE_HASH_H
#include <stdint.h>
#define VF_FILES 2u
#define VF_CHUNK_MAX 49152u
#define VF_ROOT_ONLY 1u
struct vf_identity {uint64_t dev,inode;int64_t size;uint32_t mode,nlink,uid,gid,mtime,mtimens,ctime,ctimens;};
struct vf_config {const char*path;uint32_t bytes,mode,flags;uint8_t sha256[32];};
union vf_sha_storage {uint64_t align;uint8_t bytes[128];};
struct vf_state {uint32_t abi,active,index,verified_mask,total_bytes,last_bytes,steps,error,close_uncertain;int32_t fd;uint32_t file_done;union vf_sha_storage sha;struct vf_identity before,snapshot[VF_FILES];};
struct vf_ports {void*context;int(*open)(void*,const char*);int(*stat)(void*,int,struct vf_identity*);int(*read)(void*,int,void*,uint32_t);int(*close)(void*,int);};
enum vf_result {VF_MORE=0,VF_DONE=1,VF_FAILED=2};
/* Pure regular-file only. Exactly2 configs. expected mode0 allows the original
 * file mode, otherwise requires exact permissions. All require regular type,
 * flashdev252:15,nlink1,size; ROOT_ONLY additionally uid/gid0. Each step hashes
 * at most48KiB; ports/func pointers are never retained between calls. */
int vf_init(struct vf_state*);
int vf_step(struct vf_state*,const struct vf_config[VF_FILES],const struct vf_ports*);
/* Close once, mark fd consumed BEFORE close. Unknown close effects are sticky;
 * never retry the descriptor. Cancel has no Sony object/UI/hardware effects. */
int vf_cancel(struct vf_state*,const struct vf_ports*);
/* Only after both digests: reopen/stat/close every exact path and compare saved
 * identity includingmtime/ctime ns. No file body read. */
int vf_revalidate(struct vf_state*,const struct vf_config[VF_FILES],const struct vf_ports*);
int vf_identity_equal(const struct vf_identity*,const struct vf_identity*);
#endif
