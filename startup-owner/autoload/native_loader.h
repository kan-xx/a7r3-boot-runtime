#ifndef A7R_TOUCH_NATIVE_LOADER_H
#define A7R_TOUCH_NATIVE_LOADER_H
#include "optional_loader.h"
#include "boot_manifest.h"
#include "verify_file_hash.h"
#include "../platform/platform.h"
struct tln_context {
 struct np_context *platform;
 void *owner_context;
 int (*eligible)(void *,uint32_t *);
 int (*activation)(void *,uint32_t *,uint32_t *);
 struct touch_boot_manifest manifest;
 uint32_t manifest_verified,artifact_verified;
 struct vf_state verifier;
 struct vf_config config[VF_FILES];
 struct vf_identity manifest_identity,owner_identity;
 uint32_t verify_steps,verify_failed,close_uncertain;
 uint32_t platform_checks,platform_error,platform_close_uncertain;
 uint32_t resolve_owner_revoked;
};
/* Construct ports, no IO. Requires the existing owner worker's exact platform
 * context. No worker, timer, power callback, ACK, or failure function is added.
 */
struct tl_port tln_ports(struct tln_context *);
#endif
