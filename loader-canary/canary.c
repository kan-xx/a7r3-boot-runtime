/* SENSER command FA00 canary: bounded reply only. No hooks or constructors. */
#include <stdint.h>
#include <stddef.h>

struct plugin_packet {
    const uint8_t *input;
    uint32_t input_size;
    uint32_t input_capacity;
    const uint8_t *output;
    uint32_t output_size;
    void (*output_free)(void *);
};
#if defined(__arm__)
_Static_assert(sizeof(struct plugin_packet) == 24, "original ARM packet ABI");
_Static_assert(offsetof(struct plugin_packet, output) == 12, "output offset");
#endif

#if defined(CANARY_HOST_TEST)
static uint32_t identity(uint32_t number) { return number == 20 ? 1234 : 5678; }
#else
static uint32_t identity(uint32_t number) {
    register uint32_t value __asm__("r0");
    register uint32_t syscall_number __asm__("r7") = number;
    __asm__ volatile("svc 0" : "=r"(value) : "r"(syscall_number) : "memory", "cc");
    return value;
}
#endif

static uint8_t reply[40];
static void put32(uint8_t *p, uint32_t value) {
    p[0] = (uint8_t)value; p[1] = (uint8_t)(value >> 8);
    p[2] = (uint8_t)(value >> 16); p[3] = (uint8_t)(value >> 24);
}

__attribute__((visibility("default")))
uint8_t commandFA00(struct plugin_packet *packet) {
    if (!packet) return 0x81;
    packet->output = 0; packet->output_size = 0; packet->output_free = 0;
    if (!packet->input || packet->input_size != 16 || packet->input_capacity < 16)
        return 0x81;
    if (packet->input[0] != 'A' || packet->input[1] != '7' ||
        packet->input[2] != 'Q' || packet->input[3] != '1') return 0x81;
    reply[0]='A'; reply[1]='7'; reply[2]='R'; reply[3]='C';
    reply[4]='A'; reply[5]='N'; reply[6]='1'; reply[7]=0;
    put32(reply+8, identity(20));
    put32(reply+12, identity(224));
    put32(reply+16, (uint32_t)(uintptr_t)&commandFA00);
    put32(reply+20, (uint32_t)(uintptr_t)__builtin_return_address(0));
    for (uint32_t i=0; i<16; ++i) reply[24+i]=packet->input[i];
    packet->output = reply; packet->output_size = sizeof reply;
    return 1;
}

#ifdef CANARY_HOST_TEST
#include <assert.h>
#include <string.h>
#include <stdio.h>
int main(void) {
    uint8_t request[16]={'A','7','Q','1',1,2,3,4,5,6,7,8,9,10,11,12};
    struct plugin_packet p={request,16,16,0,0,0};
    assert(commandFA00(&p)==1 && p.output_size==40 && !p.output_free);
    assert(!memcmp(p.output,"A7RCAN1",8) && !memcmp(p.output+24,request,16));
    assert(p.output[8]==0xd2 && p.output[9]==4);
    for (unsigned n=0;n<33;n++) {
        p.input_size=n;
        assert(commandFA00(&p)==(n==16?1:0x81));
        if(n!=16) assert(!p.output && !p.output_size && !p.output_free);
    }
    p.input_size=16;
    for (unsigned cap=0;cap<16;cap++) {
        p.input_capacity=cap;
        assert(commandFA00(&p)==0x81 && !p.output && !p.output_size);
    }
    p.input_capacity=16;request[0]='X'; assert(commandFA00(&p)==0x81);
    request[0]='A';p.input=0;assert(commandFA00(&p)==0x81);
    assert(commandFA00(0)==0x81);
    puts("Canary valid and 51 invalid input cases passed");
    return 0;
}
#endif
