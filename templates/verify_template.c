#include "decomp.c"
#include <stdio.h>

// If cprover sees stdlib, it gets radically slower.
#ifndef __CPROVER__
#include <stdlib.h>
#endif

int main()
{

    CPUState state;
    state.reg = malloc(0x2000);
    state.unique = malloc(0x200000);
    state.ram = malloc(0x200000);

    // Initialize state here
    // Uninitialized variables are nondeterministically chosen
    // state.pc = MY_FUNCTION_ADDR; /* Initialize function address to */;

    // Run decompiled function
    // my_function(&state, -1);

    // Check assertions here
    // assert(*(uint64_t*)(state.reg + RAX) == 0xdeadbeef);
    // assert(*(uint64_t*)(state.ram + FOO_ADDR) <= 0xBADDCAFE);
    return 0;
}