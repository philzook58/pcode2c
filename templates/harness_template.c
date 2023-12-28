#include "decomp.c"
#include <stdio.h>

int main()
{

    CPUState state;
    uint8_t reg[0x2000] = {0};
    uint8_t unique[0x200000];
    uint8_t ram[1024] = {0};
    state.reg = reg;
    state.unique = unique;
    state.ram = ram;
    // Initialize state here
    // Uninitialized variables are nondeterministically chosen
    state.pc = /* TODO: Function address */;

    // Run decompiled function
    FUNCTION(&state, -1);

    // Check assertions here
    assert(1 == 0);
    return 0;
}