#ifndef A7_OWNER_REPORT_CACHE_H
#define A7_OWNER_REPORT_CACHE_H
#include <stdint.h>

#define OWNER_REPORT_WORDS 2048u
#define OWNER_REPORT_BYTES 8192u
#define OWNER_REPORT_ATTEMPTS 4u

/* One publisher, any number of readers. All shared words use __atomic ports.
 * Zero-initialize before concurrent use; do not reset or copy the cache live.
 * The caller owns storage; there is no allocation, thread, lock, IO or ACK.
 * A read must not span a complete generation cycle (2^32-2 publications).
 * UINT32_MAX -> 2 skips zero and preserves alternating index = generation&1.
 */
struct owner_report_cache {
    uint32_t generation;
    uint32_t words[2][OWNER_REPORT_WORDS];
};

/* frame/out must be valid 8192-byte arrays outside the cache. The publisher's
 * frame must not be concurrently changed while publish is copying it.
 * publish: 0 complete, -1 bad parameter; sole publisher only.
 * report: 0 coherent complete frame, 1 not yet published or concurrent change,
 *        -1 bad parameter. Output on nonzero is unspecified; never consume it.
 * report can return a prior complete frame while the publisher is interrupted.
 * The owner worker may call report into a separate local/export buffer too.
 */
int owner_report_cache_publish(struct owner_report_cache *,
                               const uint32_t *frame, unsigned bytes);
int owner_report_cache_report(const struct owner_report_cache *,
                              uint32_t *out, unsigned bytes);

#ifdef OWNER_REPORT_CACHE_TEST_HOOKS
enum owner_report_test_stage {
    ORC_WRITE_BEGIN=1, ORC_WRITE_WORD=2, ORC_WRITE_READY=3,
    ORC_WRITE_PUBLISHED=4, ORC_READ_BEGIN=5, ORC_READ_WORD=6,
    ORC_READ_VERIFY=7
};
void owner_report_cache_test_hook(unsigned stage, unsigned index,
                                 const struct owner_report_cache *);
#endif
#endif
