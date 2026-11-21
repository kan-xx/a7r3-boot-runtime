#include <stdint.h>
extern long syscall(long,...);extern void A7R_Lifecycle_Finalize(void);
static uint32_t pid,armed;
__attribute__((visibility("default")))int a7r_full_exit_bridge_v14(uint32_t expected_pid){
 if(!expected_pid||expected_pid!=(uint32_t)syscall(20))return -1;uint32_t zero=0;
 if(!__atomic_compare_exchange_n(&armed,&zero,1,0,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))return -1;
 pid=expected_pid;__atomic_store_n(&armed,2,__ATOMIC_RELEASE);return 0;
}
__attribute__((destructor))static void retire(void){if(__atomic_load_n(&armed,__ATOMIC_ACQUIRE)==2&&pid==(uint32_t)syscall(20))A7R_Lifecycle_Finalize();}
