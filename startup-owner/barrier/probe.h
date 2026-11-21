#ifndef A7_BARRIER_PROBE_H
#define A7_BARRIER_PROBE_H
#include <stdint.h>
#include <stddef.h>
struct bp_report {uint32_t abi,bytes,stage,error,pid,tid,reply_sid,source_sid,send_calls,receive_calls,free_calls,delete_calls,last_rc,reply_capacity,reply_source,retained_ids,loop_ok,barrier_ok,notify_unchanged,anchors,before[4],after[4],reply[8],held_message,held_destination;};
struct bp_ports {int(*id)(unsigned,unsigned,uintptr_t);int(*alloc)(unsigned,void**,unsigned,unsigned);int(*send)(unsigned,void*);int(*free)(unsigned,void*);int(*recv)(unsigned,void**,int);int(*size)(void*);int(*policy)(uint32_t*);void(*delay)(void);};
int bp_run(const struct bp_ports*,struct bp_report*);
#endif
