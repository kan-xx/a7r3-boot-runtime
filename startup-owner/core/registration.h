#ifndef A7_REGISTERED_OWNER_LEASE_H
#define A7_REGISTERED_OWNER_LEASE_H
#include <stdint.h>
#define RL_BUILD 0x2917cc21u
#define RL_MARKER 0xa7cc0001u
enum {RL_OK=0,RL_BUSY=1,RL_ALREADY=2,RL_ERROR=-1};
struct rl_ports {
 void*context;uint32_t(*tid)(void*);
 int(*read)(void*,uint32_t,uint32_t*,uint32_t);
 int(*try_sem)(void*,uint32_t);int(*signal_sem)(void*,uint32_t);
 uint32_t(*find_entry)(void*,uint32_t,uint32_t);
 int(*add_reference)(void*,uint32_t,uint32_t);
};
struct rl_config {struct rl_ports port;uint32_t pid,worker_tid,descriptor,handle,target_mask,descriptor_words[11];};
struct rl_state {uint32_t pid,descriptor,module_id,type,state,pending;};
struct rl_status {uint32_t abi,bytes,build,error,attempted,owns_reference,node,reference,reference_count,node_sem,global_held,node_held,reads,add_calls,last_rc;};
struct rl_control {struct rl_config cfg;uint32_t initialized;struct rl_status status;};
#define RL_EXPORT __attribute__((visibility("default")))
RL_EXPORT uint32_t rl_size(void);
RL_EXPORT int rl_init(struct rl_control*,const struct rl_config*);
RL_EXPORT int rl_acquire(struct rl_control*);
RL_EXPORT int rl_snapshot(struct rl_control*,uint32_t,struct rl_state*);
RL_EXPORT int rl_report(const struct rl_control*,struct rl_status*);
/* One bootstrap/owner worker only. Native binding must authenticate exact im,
 * candidate IMDB, own held loader handle and original function addresses.
 * read validates every readable range; try_sem is a SINGLE no-wait attempt.
 * add_reference is original im bd18 under original global+node semaphores.
 * There is deliberately NO release API: retain our canonical reference until
 * process termination. This does not pin provider libraries or permit unload.
 * Main-thread state/counter writes are not protected by the registry semaphore;
 * snapshot protects identity/lifetime, while original main protocol and the
 * coordinator's generation/claim checks order the completion transaction. */
#endif
