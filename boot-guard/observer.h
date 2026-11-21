#ifndef A7R_BOOT_OBSERVER_H
#define A7R_BOOT_OBSERVER_H
#include <stdint.h>
#define BO_MAGIC 0x314f4241u
#define BO_BUILD 0x3110e115u
#ifndef BO_DIR
#define BO_DIR "a7r3-startup-full-v14"
#endif
struct bo_record {
 uint32_t magic,abi,build,bytes;uint8_t installation[16];
 uint32_t launcher_pid,shell_pid,observer_parent,worker_pid,worker_ppid_before,worker_ppid_after,uid,ancestry_qualified;
 uint64_t launcher_start,shell_start,mono_begin_ns,mono_end_ns;
 uint32_t boot_id_bytes,im_pid,im_seen,status,flags,reserved[3];
 uint64_t im_start;char boot_id[40];uint8_t launcher_sha[32],shell_sha[32],tail[16];
};
_Static_assert(sizeof(struct bo_record)==256,"boot observer record");
#endif
