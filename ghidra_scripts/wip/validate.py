# Is it even possible to auto run some kind of validation

# just so many things can go wrong and it's enough work that it isn't clear it's worth it.
harness = """
#include <assert.h>
#include <stdint.h>
// #include <stdio.h>
// #include <stdlib.h>



typ1 global1;
typ2 global2;
typ3 global3;

{decomp}

{pcode2c}

int main(){
    CPUState state;
    init_state(&state);

    //better because state.mem will be chaosed
    global1 = state.mem[global1_addr]
    //state.mem[global1_addr] = global1;
    //state.mem[global2_addr] = global2;
    {global_init}

    retval2 = ghidra_decomp(int state.rdi, state.rsi)
    pcode2c(&state, -1);
    retval1 = state.rax;

    assert(retval == retval2);
    assert(state.mem[global1_addr] == global1);
    assert(state.mem[global2_addr] == global2);
    ...
}

"""

"""
}

"""
