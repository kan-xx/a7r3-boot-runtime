#ifndef A7R_OPTIONAL_TOUCH_LOADER_H
#define A7R_OPTIONAL_TOUCH_LOADER_H
#include <stdint.h>

/* One-shot optional extension of the existing owner worker, never a separate
 * lifecycle participant. The accepted owner is not modified by these files.
 * The future native port verifies an external protected manifest and exact
 * module bytes. This breaks the owner/core hash cycle: finalize the owner,
 * regenerate its power layout, build core, then seal the external manifest.
 */
enum tl_stage { TL_IDLE=0, TL_REVOKED=1, TL_VERIFY_FAILED=2,
 TL_LOAD_FAILED=3, TL_RESOLVE_FAILED=4, TL_ENTRY_RETURNED=5,
 TL_SAFE_BUSY=6, TL_BUSY_EXHAUSTED=7,TL_PREPARING=8,
 TL_PREPARING_EXHAUSTED=9,TL_CANCEL_UNKNOWN=10,TL_VERIFYING=11,
 TL_VERIFY_EXHAUSTED=12,TL_VERIFY_CANCEL_UNKNOWN=13,
 TL_ACTIVATION_PENDING=14,TL_ACTIVATION_EXHAUSTED=15 };
#define TL_VERIFY_FAILED_RESULT 0
#define TL_VERIFY_DONE 1
#define TL_VERIFY_MORE 2
#define TL_MAX_VERIFY_STEPS 128u
#define TL_ENTRY_SAFE_BUSY 0x7001u
#define TL_ENTRY_PREPARING 0x7003u
#define TL_ENTRY_CANCELLED 0x7004u
#define TL_ENTRY_ACTIVATION_PENDING 0x7005u
#define TL_MAX_ACTIVATION_RESULTS 50u
#define TL_MAX_SAFE_BUSY_RESULTS 50u
#define TL_MAX_PREPARING_RESULTS 2048u
#define TL_MAX_ENTRY_CALLS TL_MAX_SAFE_BUSY_RESULTS
typedef int (*tl_entry)(void *borrowed_handle, uint32_t trusted_ui_tid);
struct tl_report {
 uint32_t abi, bytes, attempted, stage, ui_tid, entered, closed,
          close_uncertain, entry_result, eligibility_lost,
          attempts, entry_calls, safe_busy_results,preparing_results,
          cancel_calls,cancel_result,verify_calls,verify_more_results,
          verify_cancel_calls,verify_cancel_result,
          activation,accepted_activation,queue_activation,queue_results,
          activation_reentries,known_core,replay_forbidden;
};
struct tl_port {
 void *context;
 /* True only for the existing native owner active/ready admission predicate.
  * Sets the current qualified UI owner TID. Must not grant on cached ready
  * alone: immediate packed lifecycle request and errors must agree. */
 int (*eligible)(void *, uint32_t *ui_tid);
 /* Exactly0 failure (native has closed its file),1 verified,2 pending.
  * At most48KiB body read per call; full verification is not rehashed later. */
 int (*verify_protected_artifact)(void *);
 void *(*load_verified)(void *);
 tl_entry (*resolve_verified_entry)(void *, void *handle);
 int (*close_owned)(void *, void *handle);
 /* Pure verification state only. Used at the128-step verification budget.
  * 1 proves fd consumed/closed,0 is uncertain and terminal. Never called for
  * temporary missing power qualification, and never a Sony/power action. */
 int (*cancel_verification)(void *);
 /* No IO/np_check: fresh existing-worker full gate proof with exact packed
  * request. Only INIT1 or nonzero generation ACT5 may be returned as qualified.
  * Used to notice a NEW ACT after0/7005 without polling native/file ports. */
 int (*activation)(void *,uint32_t *ui_tid,uint32_t *packed_request);
 /* Only the resolve-front cheap owner gate was lost, before symbol/np IO.
  * No generic resolution/check failure may set this no-IO discriminator. */
 int (*resolve_revoked)(void *);
};
void tl_init(struct tl_report *);
/* Caller serializes calls on the already existing owner worker. Each positive
 * admission claims each attempt BEFORE IO. Only explicit SAFE_BUSY7001 with
 * a successful caller close permits another step (at most50 SAFE_BUSY results).
 * Explicit PREPARING7003 is a separate pure-data session with independent pin,
 * NO native callback/hook and at most48KiB firmware data per call. At most2048
 * PREPARING results; the last call, still holding the caller ref, cancels with
 * entry(handle,0). Only CANCELLED7004 proves pure-state cleanup. Temporarily
 * missing qualification pauses progress without touching that pure state.
 * Owner invokes a step at most once per existing20ms worker iteration; no new
 * timer or worker. No retry after accepted/terminal/uncertain entry or close.
 * Every loaded caller ref is closed exactly once. Core must independently pin
 * itself before publishing any callback, even on a partial initialization error.
 */
int tl_step(struct tl_report *, const struct tl_port *);
#endif
