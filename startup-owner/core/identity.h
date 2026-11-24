#define OWNER_BUILD 0x3110f20eu
#define READY_DIR "/tmp/a7r3-startup-full-v14"
#define ENTRY_RECORD "/tmp/a7r-00112233445566778899aabbccddeeff-entry.bin"
#define FAILURE_RECORD "/tmp/a7r-00112233445566778899aabbccddeeff-failure.bin"
static const unsigned char installation[]={0,17,34,51,68,85,102,119,136,153,170,187,204,221,238,255};
/* Stock im.elf FW 3.10 bd18 reference-registration anchor */
static const unsigned char ref_anchor[]={45,233,240,65,0,175,136,70,255,247,244,254,5,70,216,177,198,104,52,70,9,224,163,104,152,69,5,209,99,104,0,32,1,51,99,96,189,232,240,129,36,104,0,44,243,209,12,32,253,247,126,233,96,177,192,248,8,128,1,35,6,96,67,96,232,96,32,70,189,232,240,129,111,240,3,0,189,232,240,129,111,240,2,0,189,232};
static const char*const db_strings[]={"/usr/lib/liba7r_startup_full_v14.so","A7R_Lifecycle_Init","A7R_Lifecycle_Exit","A7R_Lifecycle_Sus","A7R_Lifecycle_Res","A7R_Lifecycle_Inact","A7R_Lifecycle_Act"};
