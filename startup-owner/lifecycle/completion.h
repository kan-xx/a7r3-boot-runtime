#ifndef A7_LIFECYCLE_COMPLETION_CHANNEL_H
#define A7_LIFECYCLE_COMPLETION_CHANNEL_H
#include <stdint.h>
#include <stddef.h>
#define LC_BUILD 0x2917cc11u
struct lc_config {
 void*context;uint32_t(*tid)(void*);
 int(*ioctl_one)(void*,int,uint32_t,void*);int(*errno_value)(void*);
 const int*fd_slot;uint32_t worker_tid,pool_lo,pool_hi;
};
struct lc_status {uint32_t abi,bytes,build,error,ioctls,allocations,send_attempts,notifications,last_command,last_rc,held_message,held_destination,pointer_valid;};
struct lc_control {struct lc_config cfg;uint32_t initialized;int borrowed_fd;struct lc_status status;};
#define LC_EXPORT __attribute__((visibility("default")))
LC_EXPORT uint32_t lc_size(void);
LC_EXPORT int lc_init(struct lc_control*,const struct lc_config*);
LC_EXPORT int lc_complete(struct lc_control*,uint32_t,uint32_t);
LC_EXPORT int lc_report(const struct lc_control*,struct lc_status*);
/* Native wrapper must pin/authenticate this config, exact libc ioctl (one
 * syscall, no OSAL retry loop), borrowed original uconf fd, same-process
 * writable mapped pool and worker identity. This is not that wrapper. Never
 * close the borrowed fd or free/retry an ambiguous retained message. */
#endif
