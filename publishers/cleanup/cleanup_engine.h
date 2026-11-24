#ifndef A7_OBSOLETE_CLEANUP_ENGINE_H
#define A7_OBSOLETE_CLEANUP_ENGINE_H
#include <stdint.h>
#ifndef CL_CUSTOM_SPECS
#define CL_COUNT 8u
#define CL_ALL_MASK ((1u<<CL_COUNT)-1u)
#define CL_BOOT ""
#define CL_PID 0u
#define CL_START 0ull
struct cl_spec {const char*name;uint32_t bytes,mode;const char*sha;};
static const struct cl_spec cl_specs[CL_COUNT]={
{"liba7r_touch_full_runtime_v7.v14-copy.so",158072u,0555u,"d706ce18284a3cfb4449de8aa4b3b62457cd993907a812738ff8da4b52c4d8ee"},
{"liba7r_touch_full_runtime_v7.v14-retained.so",158072u,0555u,"d706ce18284a3cfb4449de8aa4b3b62457cd993907a812738ff8da4b52c4d8ee"},
{"a7r_touch_boot_v1.v14-copy.bin",128u,0444u,"8344d959f14b3a064a80feff14ea24525e172b45e10c2aba248c787de5ea51fe"},
{"a7r_touch_boot_v1.v14-retained.bin",128u,0444u,"8344d959f14b3a064a80feff14ea24525e172b45e10c2aba248c787de5ea51fe"},
{"a7r_touch_boot_v1.v8-copy.bin",128u,0444u,"c91b0f83436afdaf84cc238e19b1dbe99f813f5ce0fd0e8b54a040b2cbf8fdff"},
{"a7r_touch_boot_v1.v8-retained.bin",128u,0444u,"c91b0f83436afdaf84cc238e19b1dbe99f813f5ce0fd0e8b54a040b2cbf8fdff"},
{"a7r_touch_boot_v1.v9-copy.bin",128u,0444u,"b8c81667959f13dea3873ac30a82dfca0f77b472bdde72b1bcb016c2cb804f3e"},
{"a7r_touch_boot_v1.v9-retained.bin",128u,0444u,"b8c81667959f13dea3873ac30a82dfca0f77b472bdde72b1bcb016c2cb804f3e"},
};
static const char*const cl_names[CL_COUNT]={"liba7r_touch_full_runtime_v7.v14-copy.so","liba7r_touch_full_runtime_v7.v14-retained.so","a7r_touch_boot_v1.v14-copy.bin","a7r_touch_boot_v1.v14-retained.bin","a7r_touch_boot_v1.v8-copy.bin","a7r_touch_boot_v1.v8-retained.bin","a7r_touch_boot_v1.v9-copy.bin","a7r_touch_boot_v1.v9-retained.bin"};
static const uint64_t cl_expected_inodes[CL_COUNT]={0};
#endif /* CL_CUSTOM_SPECS */
struct cl_identity {uint64_t dev,ino,size;uint32_t mode,uid,gid,nlink;int64_t mtime,ctime;uint32_t mtime_ns,ctime_ns;uint8_t sha[32];};
struct cl_api {
 void*context;
 int(*readonly)(void*);int(*qualify)(void*);int(*root_namespace)(void*);
 int(*remount)(void*,int);
 int(*open_candidate)(void*,unsigned);
 int(*identify)(void*,int,struct cl_identity*);
 int(*namespace_same)(void*,unsigned,int,const struct cl_identity*);
 int(*references)(void*,const struct cl_identity[CL_COUNT],const int[CL_COUNT]);
 int(*unlink_candidate)(void*,unsigned);
 int(*absent)(void*,unsigned);
 int(*sync_dirs)(void*);
 int(*close_candidate)(void*,int);
};
enum {CL_OK=0,CL_INVALID=10,CL_QUALIFY=11,CL_CANDIDATE=12,CL_DISTINCT=13,CL_REFERENCED=14,CL_MOUNT=15,CL_CHANGED=16,CL_UNLINK=17,CL_SYNC=18,CL_CLOSE=19,CL_READONLY=20};
struct cl_result {uint32_t code,verified,deleted,readonly,rw_attempted,close_uncertain;struct cl_identity identity[CL_COUNT];};
int cl_same(const struct cl_identity*,const struct cl_identity*);
int cl_run(const struct cl_api*,int,struct cl_result*);
#endif
