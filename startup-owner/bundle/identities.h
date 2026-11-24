/* Custom bundle DSOs (bytes == 0) are verified via ARM32 ET_DYN ELF header,
 * dladdr() module ownership, api_memory() function-table ownership, and ABI
 * BUILD tags; stock Sony libObj.so retains exact FW 3.10 SHA-256 verification. */
static const struct spec specs[]={
{"/usr/lib/liba7r_sd_refresh_runtime_v2.so","a7r_sd_refresh_runtime_v2",0,0,{0},{0}},
{"/usr/lib/liba7r_sd_refresh_review.so","",0,0,{0},{0}},
{"/usr/lib/liba7r_exposure_observer_v2.so","a7r_exposure_observer_v2",0,0,{0},{0}},
{"/usr/lib/liba7r_capture_fresh_v12.so","a7r_capture_fresh_v12",0,0,{0},{0}},
{"/usr/lib/liba7r_menu_product_v21.so","a7r_menu_bootstrap_v21",0,0,{0},{0}},
{"/usr/lib/libObj.so","timerManager",19483804,19745484,{148,206,110,196,124,43,57,74,161,164,247,129,191,179,233,236,51,55,246,162,184,85,143,160,37,244,46,135,178,221,161,155},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}},
};
