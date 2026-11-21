#include "owner_report_cache.h"
#ifdef OWNER_REPORT_CACHE_TEST_HOOKS
#define OBSERVE(stage,index,c) owner_report_cache_test_hook((stage),(index),(c))
#else
#define OBSERVE(stage,index,c) ((void)0)
#endif

int owner_report_cache_publish(struct owner_report_cache *cache,
                               const uint32_t *frame, unsigned bytes) {
    if (!cache || !frame || bytes!=OWNER_REPORT_BYTES) return -1;
    uint32_t previous=__atomic_load_n(&cache->generation,__ATOMIC_RELAXED);
    uint32_t next=previous+1u;
    if (!next) next=2u;
    uint32_t *target=cache->words[next&1u];
    OBSERVE(ORC_WRITE_BEGIN,next,cache);
    /* Order the preceding publication before this buffer can be overwritten.
     * If a reader sees one of these stores, its post-copy acquire fence must
     * also observe at least the preceding generation at final verification.
     * The end-of-frame release alone does not order later overwrite stores. */
    __atomic_thread_fence(__ATOMIC_RELEASE);
    for (unsigned i=0;i<OWNER_REPORT_WORDS;i++) {
        __atomic_store_n(target+i,frame[i],__ATOMIC_RELAXED);
        OBSERVE(ORC_WRITE_WORD,i,cache);
    }
    OBSERVE(ORC_WRITE_READY,next,cache);
    __atomic_store_n(&cache->generation,next,__ATOMIC_RELEASE);
    OBSERVE(ORC_WRITE_PUBLISHED,next,cache);
    return 0;
}

int owner_report_cache_report(const struct owner_report_cache *cache,
                              uint32_t *out, unsigned bytes) {
    if (!cache || !out || bytes!=OWNER_REPORT_BYTES) return -1;
    for (unsigned attempt=0;attempt<OWNER_REPORT_ATTEMPTS;attempt++) {
        uint32_t before=__atomic_load_n(&cache->generation,__ATOMIC_ACQUIRE);
        OBSERVE(ORC_READ_BEGIN,attempt,cache);
        if (!before) continue;
        const uint32_t *source=cache->words[before&1u];
        for (unsigned i=0;i<OWNER_REPORT_WORDS;i++) {
            out[i]=__atomic_load_n(source+i,__ATOMIC_RELAXED);
            OBSERVE(ORC_READ_WORD,i,cache);
        }
        /* Keep all payload loads before the final generation verification. */
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        OBSERVE(ORC_READ_VERIFY,attempt,cache);
        uint32_t after=__atomic_load_n(&cache->generation,__ATOMIC_ACQUIRE);
        if (before==after) return 0;
    }
    return 1;
}
