#ifndef A7R_NATIVE_BARRIER_PORTS_H
#define A7R_NATIVE_BARRIER_PORTS_H
#include "../platform/platform.h"
#include "probe.h"
struct nb_config {struct np_context *platform;int(*ioctl_one)(int,unsigned long,...);int*(*errno_address)(void);int(*local_id)(unsigned,unsigned,uintptr_t);int(*policy)(uint32_t*);void(*delay)(void);};
struct nb_status {uint32_t calls,last_op,last_rc,error,reply_sid,source_sid,retained,initialized;};
int nb_bind(const struct nb_config*);
const struct bp_ports*nb_ports(void);
const struct nb_status*nb_report(void);
/* One worker, one barrier in flight. All kernel operations are one ioctl;
 * allocate and receive use wait0. Original user-domain ID allocation uses
 * its original in-process bitmap/lock path, not a kernel-ID substitution.
 * Caller retains platform/context/providers for process lifetime after use.
 * Sampled map checks do not establish an independent mmap lifetime pin. */
#endif
