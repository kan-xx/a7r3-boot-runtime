#ifndef A7R_TOUCH_PUBLICATION_IDENTITY_H
#define A7R_TOUCH_PUBLICATION_IDENTITY_H
#define NEW_OWNER_BYTES 79028u
#define NEW_OWNER_SHA "c68e7109605b4e148b9c5598bf61fb81158883133fdf31b248dd076bd43f5cbb"
#define ACCEPTED_REGISTRY_SHA "f2620309212756f6e59d008796a38931e18ac352bf2f1c74d9bafe5f65d8e23b"
static const unsigned char accepted_installation[16]={0,17,34,51,68,85,102,119,136,153,170,187,204,221,238,255};
struct dep{const char*path;unsigned bytes,uid,gid,mode;const char*hash;};
static const struct dep immutable_dependencies[]={
{"/usr/lib/libIMDB.so",61840,57285,1000,365,"f2620309212756f6e59d008796a38931e18ac352bf2f1c74d9bafe5f65d8e23b"},
{"/usr/bin/a7r-boot-guard-v21.elf",51924,0,0,365,"487769701e80942f8bf339350bd0ce968d3352a5c4807261989b4a48b6fe1d95"},
{"/usr/lib/liba7r_sd_refresh_review.so",8048,0,0,292,"1c2e9fe811a02e6a32773f507e07b8b6acaf226798b9158fc6ab7b73c9db57fd"},
{"/usr/lib/liba7r_sd_refresh_runtime_v2.so",11416,0,0,292,"b7d03249160ef314053eb6f89520315c9694a93fc2a11653f4c90773abd7f4b6"},
{"/usr/lib/liba7r_capture_fresh_v12.so",93468,0,0,365,"f322d3e9f509e525b2072beec7bcc21461b0f4fd36b35997ba1e168230398949"},
{"/usr/lib/liba7r_menu_product_v21.so",70160,0,0,365,"c67529ca3cc2b15dc176af58975a0c8ec841c68a846359a5560c0eb7f4a25aac"},
{"/usr/lib/liba7r_startup_full_v14.so",79028,0,0,365,"c68e7109605b4e148b9c5598bf61fb81158883133fdf31b248dd076bd43f5cbb"},
{"/usr/lib/liba7r_touch_full_runtime_v7.so",160344,0,0,365,"b5fbfc1603fe54125decf28000cc76e97d058e413b97a5de6d88a28aa2cc0f78"},
{"/usr/lib/a7r_touch_boot_v1.bin",128,0,0,292,"be1425edc12889d6bd244da716343ac284e7c6f5b4bc318907d799fa8b39b470"},
};
#endif
