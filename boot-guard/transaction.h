#ifndef A7R_GUARD_TRANSACTION_H
#define A7R_GUARD_TRANSACTION_H
#include <stdint.h>
enum {GX_STOCK=0,GX_CONFIRMED=1,GX_RESTORED=2,GX_INVALID=10,GX_SOURCE=11,GX_TARGET=12,GX_CHANGED=13,GX_MOUNT=14,GX_RENAME=15,GX_DURABILITY=16,GX_READONLY=17,GX_RETAIN=18};
enum {GX_STARTED=1,GX_ACCEPTED=2,GX_RESTORE_INTENT=3,GX_READY=4,GX_DONE=5,GX_FAILURE=6};
struct gx_record {
 char magic[8];uint32_t abi,bytes;uint64_t seq;uint32_t phase,code;
 unsigned char nonce[16];char boot[40];unsigned char candidate[32];
 uint32_t pid;unsigned char extra[100],digest[32];
};
_Static_assert(sizeof(struct gx_record)==256,"journal ABI");
struct gx_config {
 const char *target,*standby,*retained;uint64_t original_bytes,candidate_bytes;
 uint32_t mode,uid,gid,ready_build,wait_ms,force_recovery;
 unsigned char nonce[16],original[32],candidate[32];char boot[40];
 void *context;int(*remount)(void*,int);int(*readonly)(void*);
 int(*ready_process)(void*,uint32_t,uint64_t);
};
struct gx_result {uint32_t code,reason,journal_error,restored,ready,readonly,attempted_rename,invalid_ready;uint64_t sequence;};
void gx_seal(struct gx_record*);
int gx_valid(const struct gx_record*,const struct gx_config*);
/* force_recovery is a private guardian decision after authenticated runtime
 * failure evidence. It never bypasses target/standby/journal/mount validation. */
int gx_run(int lib,int journal,const struct gx_config*,struct gx_result*);
#endif
