#ifndef A7R_TOUCH_PUBLICATION_IDENTITY_H
#define A7R_TOUCH_PUBLICATION_IDENTITY_H
#define NEW_OWNER_BYTES 79028u
#define NEW_OWNER_SHA "48771aa2216fd7b24b544f2b36abb65e9b97dc39a406d70bae1020fbeb757375"
#define ACCEPTED_REGISTRY_SHA "f2620309212756f6e59d008796a38931e18ac352bf2f1c74d9bafe5f65d8e23b"
static const unsigned char accepted_installation[16]={0,17,34,51,68,85,102,119,136,153,170,187,204,221,238,255};
struct dep {const char*path;unsigned bytes,uid,gid,mode;const char*hash;};
static const struct dep immutable_dependencies[]={
{"/usr/lib/libIMDB.so",61840,57285,1000,365,"f2620309212756f6e59d008796a38931e18ac352bf2f1c74d9bafe5f65d8e23b"},
{"/usr/lib/liba7r_capture_fresh_v12.so",93404,0,0,365,"634b6f2291a81cf7f71fb8c8e42bbfbbef8bb413a1174e0dab7d6d9ddbcc8a10"},
{"/usr/lib/liba7r_menu_product_v21.so",70160,0,0,365,"3aa925564d548cd0b93b604e1fd6dc9aa70955edc0c3f0e685c2be4a215620d7"},
{"/usr/bin/a7r-boot-guard-v21.elf",51924,0,0,365,"487769701e80942f8bf339350bd0ce968d3352a5c4807261989b4a48b6fe1d95"},
{"/usr/lib/liba7r_touch_full_runtime_v7.so",122624,0,0,365,"af51bc62419889f93f0008f3b9d446507a710800f2986e49d8c0d9b9410cc26b"},
{"/usr/lib/a7r_touch_boot_v1.bin",128,0,0,292,"b8c81667959f13dea3873ac30a82dfca0f77b472bdde72b1bcb016c2cb804f3e"},
};
#endif
