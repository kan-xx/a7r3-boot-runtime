/* Host ASan/UBSan test for exit-bridge/loader.c post-dlopen maps refresh. */
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define LATE_SPEC_DEFINED 1
#define LATE_CUSTOM_SPECS 1
struct late_spec {const char*path;uint32_t bytes,offset;uint8_t hash[32],anchor[16];};
static struct late_spec late_specs[4]={
 {"/usr/lib/viewUnified2.so",64,0,{0},{0}},
 {"/usr/lib/CautionConfig.so",64,0,{0},{0}},
 {"/usr/lib/dataflowInfraFramework.so",64,0,{0},{0}},
 {"/usr/lib/liba7r_full_exit_bridge_v14.so",64,66296,{0},{48,72,45,233,0,64,224,227,0,0,80,227,19,0,0,10}},
};

long late_fixture_syscall(long op, ...);
void* late_fixture_dlopen(const char* p, int flag);
void* late_fixture_dlsym(void* p, const char* n);
struct late_info;
int late_fixture_dladdr(const void* p, struct late_info* d);

#define syscall late_fixture_syscall
#define dlopen late_fixture_dlopen
#define dlsym late_fixture_dlsym
#define dladdr late_fixture_dladdr
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpointer-to-int-cast"
#include "../exit-bridge/loader.c"
#pragma clang diagnostic pop
#undef syscall
#undef dlopen
#undef dlsym
#undef dladdr

static unsigned opened_bridge, known_bridge, checks, denied, armed, suppress_refresh;
static uint8_t synthetic_files[4][64];
static unsigned synthetic_pos[4];
static int arm_fn(uint32_t pid) { assert(pid == 151 && !armed); armed = 1; return 0; }

long late_fixture_syscall(long op, ...) {
 va_list ap; va_start(ap, op); long r = -1;
 if (op == 20) r = 151;
 else if (op == 224) r = 900;
 else if (op == 5) {
  const char* p = va_arg(ap, const char*);
  unsigned f = va_arg(ap, unsigned);
  assert(f == 0x88000);
  for (unsigned i = 0; i < 4; i++) {
   if (!strcmp(p, late_specs[i].path)) { synthetic_pos[i] = 0; r = 100 + (int)i; break; }
  }
 } else if (op == 3) {
  int fd = va_arg(ap, int); void* b = va_arg(ap, void*); unsigned n = va_arg(ap, unsigned);
  unsigned idx = (unsigned)(fd - 100); assert(idx < 4);
  unsigned rem = 64 - synthetic_pos[idx];
  unsigned take = n < rem ? n : rem;
  if (take) memcpy(b, synthetic_files[idx] + synthetic_pos[idx], take);
  synthetic_pos[idx] += take;
  r = take;
 } else if (op == 6) {
  int fd = va_arg(ap, int); assert(fd >= 100 && fd < 104); r = 0;
 } else assert(0);
 va_end(ap);
 return r;
}

int np_check(struct np_context* p) {
 assert(p->s.pid == 151 && p->s.worker_tid == 900);
 checks++;
 if (!suppress_refresh) known_bridge = opened_bridge;
 return 0;
}

int np_read(struct np_context* p, uint32_t a, void* b, uint32_t n) {
 (void)p; (void)a; assert(n == 16);
 if (!known_bridge) { denied++; return -1; }
 memcpy(b, late_specs[3].anchor, 16);
 return 0;
}

void* late_fixture_dlopen(const char* p, int flag) {
 unsigned which = 4;
 for (unsigned i = 0; i < 4; i++) if (!strcmp(p, late_specs[i].path)) which = i;
 assert(which < 4);
 assert(flag == (which == 3 ? 2 : 6));
 if (which == 3) opened_bridge = 1;
 return (void*)(uintptr_t)(0x1000 + which);
}

void* late_fixture_dlsym(void* p, const char* n) {
 assert(p == (void*)0x1003 && !strcmp(n, "a7r_full_exit_bridge_v14"));
 return (void*)arm_fn;
}

int late_fixture_dladdr(const void* p, struct late_info* d) {
 assert(p == (const void*)arm_fn);
 *d = (struct late_info){
  late_specs[3].path,
  (void*)((uintptr_t)arm_fn - late_specs[3].offset),
  "a7r_full_exit_bridge_v14",
  (void*)arm_fn
 };
 return 1;
}

int main(void) {
 for (unsigned i = 0; i < 4; i++) {
  for (unsigned k = 0; k < 64; k++) synthetic_files[i][k] = (uint8_t)(i * 19 + k);
  struct sha256 h; sha_init(&h); sha_add(&h, synthetic_files[i], 64);
  sha_end(&h, late_specs[i].hash);
 }

 /* Scenario 0: simulate pre-fix stale maps (suppress_refresh=1 -> error 6) */
 suppress_refresh = 1;
 struct np_context p = {0}; p.s.pid = 151; p.s.worker_tid = 900;
 int r = late_open(&p);
 const struct late_status* s = late_report();
 assert(r == -1 && s->error == 6 && s->pins == 15 && checks == 2 && denied == 1 && !armed);

 /* Scenario 1: post-dlopen np_check refreshes maps -> armed=1, error=0 */
 memset(pins, 0, sizeof pins);
 memset(&status, 0, sizeof status);
 opened_bridge = known_bridge = checks = denied = armed = suppress_refresh = 0;
 r = late_open(&p);
 assert(!r && s->stage == 5 && !s->error && s->armed && s->pins == 15 && checks == 2 && !denied && armed);
 printf("LATE_LOADER_TEST passed=1 checks=%u post_dlopen_mapping_requalified=1\n", checks);
 return 0;
}
