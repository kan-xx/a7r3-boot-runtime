#ifndef A7R_SEM_PORT_H
#define A7R_SEM_PORT_H
#include <stdint.h>
#define SP_GLOBAL 0x9401c3u
#define SP_REJECT (-4095)
struct sp_status {uint32_t abi,bytes,acquire_calls,release_calls,ioctls,global_owned,node_owned,node_id,global_attempted,node_attempted,rejections;int32_t last_rc;};
struct sp_port {void*ctx;int(*check)(void*);int(*release_check)(void*);int(*invoke)(void*,uint32_t,uint32_t);uint32_t(*node)(void*);int(*held)(void*,uint32_t);};
struct sp_control {struct sp_port port;struct sp_status status;};
void sp_init(struct sp_control*,const struct sp_port*);
int sp_acquire(struct sp_control*,uint32_t);
int sp_release(struct sp_control*,uint32_t);
#endif
