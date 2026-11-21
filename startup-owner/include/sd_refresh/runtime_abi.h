#ifndef A7_REFRESH_RUNTIME_ABI_H
#define A7_REFRESH_RUNTIME_ABI_H
#include "sd_refresh.h"
#define RR_ABI 1u
#define RR_BUILD 0x29110402u
#define RR_RUNTIME_PATH "/usr/lib/liba7r_sd_refresh_runtime_v2.so"
#define RR_CORE_PATH "/usr/lib/liba7r_sd_refresh_review.so"
#define RR_SYMBOL "a7r_sd_refresh_runtime_v2"
#define RR_REQUEST_BYTES 80u
#define RR_REPLY_BYTES 4640u
#define RR_DATA_OFFSET 544u
#define RR_NOLOAD 6
/* Every client owns a dlopen/NOLOAD reference until its last call returns.
 * Only start transfers an explicitly owned reference to the resident host. */
enum rr_operation {RR_START=1,RR_QUERY=2,RR_REFRESH=3,RR_CANCEL=4,RR_SELECT=5,RR_AUDIT=6,RR_STOP=7};
enum rr_error {RR_OK=0,RR_ABSENT=0x100,RR_ABI_ERROR=0x101,RR_PENDING=0x102,RR_STATE_ERROR=0x103,RR_BIND_ERROR=0x104,RR_INIT_ERROR=0x105,RR_WAKE_ERROR=0x106,RR_CLOSE_ERROR=0x107,RR_INSTANCE_ERROR=0x108,RR_REF_UNCERTAIN=0x109};
enum rr_phase {RR_COLD=0,RR_STARTING=1,RR_RUNNING=2,RR_STOPPING=3,RR_HELD=4,RR_CLAIMED=5,RR_STOPPED=6,RR_INIT_FAILED=7};
struct rr_request {uint32_t op,control,generation,desired,offset,length,reserved[2];uint8_t instance[16],nonce[16];};
struct rr_status {
 uint32_t abi,bytes,state,stage,error,thread_created,thread_exited,thread_joined;
 uint32_t worker_result,wake_error,stop_requested,owns_self,owns_fsys,owns_pthread,owns_core,owns_libc;
 uint32_t active_calls,context_bytes,fsys_base,pthread_base,core_base,worker_tid;
 uint8_t instance[16];uint32_t stop_ticket,reference_uncertain,pipe_owned_mask,core_query_result,bind_detail,bind_index;
};
struct rr_report {struct rr_status runtime;struct sr_status core;struct sr_audit audit;};
_Static_assert(sizeof(struct rr_request)==64,"runtime request ABI");
_Static_assert(sizeof(struct rr_status)==128,"runtime status ABI");
_Static_assert(sizeof(struct rr_report)==412,"runtime report ABI");
struct rr_api {
 uint32_t abi,bytes,build;
 int (*start)(void *,const struct rr_request *,uint32_t *,struct rr_report *);
 int (*dispatch)(const struct rr_request *,struct rr_report *,void *);
 int (*claim_stop)(const struct rr_request *,void **,uint32_t *,struct rr_report *);
 int (*finish_stop)(uint32_t,int,struct rr_report *);
};
typedef const struct rr_api *(*rr_get_api)(void);
struct rr_packet {const uint8_t *input;uint32_t size,capacity;const uint8_t *output;uint32_t length;void (*freefn)(void*);};
#endif
