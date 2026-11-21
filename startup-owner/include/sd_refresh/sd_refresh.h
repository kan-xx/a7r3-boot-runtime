#ifndef A7_SD_REFRESH_H
#define A7_SD_REFRESH_H
#include <stdint.h>
#include <stddef.h>
#define SR_ABI 1u
#define SR_BYTES 22592u
#define SR_CHUNK 4096u
/* Native functions are borrowed. The host pins their providers and this module
 * from initialize until stop returns OK; no Fsys init/mount/global cancellation.
 * worker_tick runs on a host-owned BACKGROUND executor, never UI/event callback.
 * All APIs except worker_tick/stop perform bounded work and may return BUSY.
 * cancel uses one atomic RMW and never waits for the worker. */
struct sr_fsys {
 int32_t (*open)(const char *,uint32_t *,uint32_t);
 int32_t (*read)(uint32_t,void *,int32_t);
 int32_t (*close)(uint32_t);
 int32_t (*info)(uint32_t,void *);
 uint32_t (*mounts)(void);
 uint16_t (*letter)(const char *);
};
enum sr_rc {SR_OK=0,SR_BUSY=1,SR_ARGUMENT=2,SR_STOPPED=3,SR_HOLD=4,SR_DUPLICATE=5,SR_STALE=6,SR_NO_AUDIT=7,SR_CANCELLED=8,SR_EXHAUSTED=9};
enum sr_phase {SR_IDLE=0,SR_QUEUED=1,SR_READING=2,SR_READY=3,SR_FAILED=4,SR_HELD=5,SR_RETIRED=6};
enum sr_error {SR_E_NONE=0,SR_E_CANCEL=1,SR_E_MAPPING=2,SR_E_MOUNT=3,SR_E_INFO=4,SR_E_MEDIA=5,SR_E_OPEN=6,SR_E_READ=7,SR_E_EOF=8,SR_E_EXTRA=9,SR_E_CLOSE_STALE=10,SR_E_CLOSE_UNKNOWN=11,SR_E_HASH=12,SR_E_PROTOCOL=13};
enum sr_close {SR_C_NONE=0,SR_C_OK=1,SR_C_INVALIDATED=2,SR_C_UNCERTAIN=3};
struct sr_asset_result {uint32_t asset,error,bytes,read_calls,max_read,handle,close_kind;int32_t raw,close_raw;uint8_t sha256[32];};
struct sr_status {
 uint32_t abi,bytes,phase,worker_active,control,snapshot_control,snapshot_generation,valid;
 uint32_t desired,effective,hold,stopping,host_lease_required,error,completed_requests;
 uint8_t request_nonce[16],snapshot_nonce[16],media_id[24];
 struct sr_asset_result asset[2];
};
_Static_assert(sizeof(struct sr_asset_result)==68,"asset wire ABI");
_Static_assert(sizeof(struct sr_status)==252,"status wire ABI");
struct sr_audit {uint32_t generation,source_control,observed_control,valid;uint8_t nonce[16];};
/* Initialize only zeroed, aligned, exclusively owned storage. Output/input
 * arguments must not overlap that storage. Reinitialization is rejected. */
size_t sr_context_bytes(void);
int sr_initialize(void *,size_t,const struct sr_fsys *);
int sr_refresh(void *,uint32_t expected_control,const uint8_t nonce[16]);
/* Invalidates admission immediately. Atomic RMW sets the cancel bit; the
 * worker/refresh owner advances the serial before admitting another request.
 * Return is always OK for an initialized object. It does not mean IO drained. */
int sr_cancel(void *);
int sr_select(void *,uint32_t expected_generation,uint32_t desired);
int sr_query(void *,struct sr_status *);
/* Tick may block inside Sony calls; repeated/concurrent ticks return BUSY.
 * It processes at most one request. If final publication lock is contended,
 * returns BUSY retaining completion; call again on the same background executor.
 * Never cancel/kill that thread. */
int sr_worker_tick(void *);
/* Audit is only a bounded copy of the last verified snapshot. May return valid=0.
 * NOT a playback lease; no API here authorizes new playback after cancellation. */
int sr_audit_copy(void *,uint32_t expected_generation,uint32_t offset,void *,uint32_t,struct sr_audit *);
/* First cancels admission. BUSY => drain ticks/calls; HOLD => unknown native
 * Close cannot be waived by this API. Only OK releases the borrowed API lifetime.
 * Caller must prevent new API callers before freeing a retired context. */
int sr_stop(void *);
#endif
