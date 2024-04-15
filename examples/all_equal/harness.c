#include "all_equal_pcode.c"
#include "x86.h"
#include <stdlib.h>

int main() {
  CPUState state;
  init_CPUState(&state);

  // Initialize state here, including pc address.
  state.pc = 0x1169;

  memset(state.reg + RDI, 1, 8);
  memset(state.reg + RSI, 64, 8);
  memset(state.reg + RDX, 64, 8);
  memset(state.reg + RCX, 0, 8);
  memset(state.reg + RAX, 0, 8);
  memset(state.reg + RSP, 0, 8);

  pcode2c(&state, -1); // Run decompiled function
  printf("RAX: %ld\n", *(uint64_t *)(state.reg + RAX));
  __CPROVER_printf("RAX: %ld\n", *(uint64_t *)(state.reg + RAX));
  assert(*(uint8_t *)(state.reg + RAX) != 0);

  return 0;
}