#include "decomp.c"
#include <stdio.h>

#define RSI 0x30
#define RDI 0x38
#define RAX 0x0
int main()
{

    CPUState state;
    uint8_t reg[1024] = {0};
    uint8_t unique[0x261000];
    uint8_t ram[1024] = {0};
    state.reg = reg;
    state.unique = unique;
    state.ram = ram;
    state.pc = 0x00100000;
    state.reg[RSI] = 10;
    state.reg[RDI] = 3;
    mymin(&state, -1);
    printf("pc: 0x%llx\n", state.pc);
    printf("RAX: %ld\n", state.reg[RAX]);
    return 0;
}