#include "../_pcode.h"
#include "pypcode/pypcode/pypcode.h/sleigh/opcodes.hh"

int interp() {
  CPUState cpu;
  init_CPUState(&cpu);
  for (;;) {
    opcode op = getopcode(state.pc);
    switch (op) {
    case COPY:
      COPY(out_addr, out_size, in_addr, in_size);
      break;
    case INT_ADD:
      INT_ADD(out_addr, out_size, in_addr1, in_size1, in_addr2, in_size2);
      break;
    case BOOL_OR:
    }
  }
}

int main(int argc, char *argv[]) {
  // parse arguments --base_address --offset --size

  // read the file

  //
  // call interp

  return 0;
}