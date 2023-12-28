#include "decomp.c"
#include "arch.h"
#include <stdio.h>
int main()
{

    CPUState state;
    uint8_t reg[0x300] = {0};
    uint8_t unique[0x261000];
    uint8_t ram[1024] = {0};
    state.reg = reg;
    state.unique = unique;
    state.ram = ram;
    state.pc = 0x00100000;
    uint8_t rsi, rdi;
    // rsi = 3;
    // rdi = 10;
    state.reg[RSI] = rsi;
    state.reg[RDI] = rdi;
    mymin(&state, -1);
    uint8_t ret = state.reg[RAX];
    assert(ret == rsi || ret == rdi);
    assert(ret <= rsi && ret <= rdi);
    printf("pc: 0x%lx\n", state.pc);
    printf("RAX: %d\n", state.reg[RAX]);
    return 0;
}