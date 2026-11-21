#ifndef A7R_READY_RECORD_H
#define A7R_READY_RECORD_H
#include <stdint.h>
/* Sony Linux arch/arm/include/asm/fcntl.h overrides asm-generic values. */
#define AR_DIRECTORY 0x4000
#define AR_NOFOLLOW 0x8000
#define AR_CLOEXEC 0x80000
#define AR_CREATE_EXCLUSIVE (AR_CLOEXEC|AR_NOFOLLOW|0xc1)
struct ar_ready_status {uint32_t stage,error,created,renamed;};
int ar_write_ready(const char*,const unsigned char*,const unsigned char*,uint32_t,uint32_t,struct ar_ready_status*);
int ar_write_failure(const char*,const unsigned char*,const unsigned char*,uint32_t,uint32_t,uint32_t,struct ar_ready_status*);
int ar_write_report(const char*,const unsigned char*,const unsigned char*,uint32_t,uint32_t,const void*,unsigned,struct ar_ready_status*);
#endif
