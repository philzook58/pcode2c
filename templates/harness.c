void main()
{
    CPUState state;
    init_CPUState(&state);

    // Initialize state here, including pc address.
    state.pc = MY_FUNCTION_ADDR;

    pcode2c(&state, -1); // Run decompiled function

    // Check assertions here: ex, assert(*(uint64_t*)(state.reg + RAX) == 0xdeadbeef);
}