#include "pcode.h"
void mymin(CPUState *state){
uint8_t* reg = state->reg; uint8_t* unique = state->unique; uint8_t* ram = state->ram;
for(;;){
switch(state->pc) {
case 0x00100000:
// ENDBR64
case 0x00100004:
// CMP RSI,RDI
	COPY(unique + 0x26100, 8, reg + 0x30 /* RSI */, 8); // (unique, 0x26100, 8) COPY (register, 0x30, 8)
	INT_LESS(reg + 0x200 /* CF */, 1, unique + 0x26100, 8, reg + 0x38 /* RDI */, 8); // (register, 0x200, 1) INT_LESS (unique, 0x26100, 8) , (register, 0x38, 8)
	INT_SBORROW(reg + 0x20b /* OF */, 1, unique + 0x26100, 8, reg + 0x38 /* RDI */, 8); // (register, 0x20b, 1) INT_SBORROW (unique, 0x26100, 8) , (register, 0x38, 8)
	INT_SUB(unique + 0x26200, 8, unique + 0x26100, 8, reg + 0x38 /* RDI */, 8); // (unique, 0x26200, 8) INT_SUB (unique, 0x26100, 8) , (register, 0x38, 8)
	INT_SLESS(reg + 0x207 /* SF */, 1, unique + 0x26200, 8, &(int64_t){0x0L}, 8); // (register, 0x207, 1) INT_SLESS (unique, 0x26200, 8) , (const, 0x0, 8)
	INT_EQUAL(reg + 0x206 /* ZF */, 1, unique + 0x26200, 8, &(int64_t){0x0L}, 8); // (register, 0x206, 1) INT_EQUAL (unique, 0x26200, 8) , (const, 0x0, 8)
	INT_AND(unique + 0x13400, 8, unique + 0x26200, 8, &(int64_t){0xffL}, 8); // (unique, 0x13400, 8) INT_AND (unique, 0x26200, 8) , (const, 0xff, 8)
	POPCOUNT(unique + 0x13480, 1, unique + 0x13400, 8); // (unique, 0x13480, 1) POPCOUNT (unique, 0x13400, 8)
	INT_AND(unique + 0x13500, 1, unique + 0x13480, 1, &(int8_t){0x1L}, 1); // (unique, 0x13500, 1) INT_AND (unique, 0x13480, 1) , (const, 0x1, 1)
	INT_EQUAL(reg + 0x202 /* PF */, 1, unique + 0x13500, 1, &(int8_t){0x0L}, 1); // (register, 0x202, 1) INT_EQUAL (unique, 0x13500, 1) , (const, 0x0, 1)
case 0x00100007:
// MOV RAX,RDI
	COPY(reg + 0x0 /* RAX */, 8, reg + 0x38 /* RDI */, 8); // (register, 0x0, 8) COPY (register, 0x38, 8)
case 0x0010000a:
// CMOVLE RAX,RSI
	INT_NOTEQUAL(unique + 0xd280, 1, reg + 0x20b /* OF */, 1, reg + 0x207 /* SF */, 1); // (unique, 0xd280, 1) INT_NOTEQUAL (register, 0x20b, 1) , (register, 0x207, 1)
	BOOL_OR(unique + 0xd380, 1, reg + 0x206 /* ZF */, 1, unique + 0xd280, 1); // (unique, 0xd380, 1) BOOL_OR (register, 0x206, 1) , (unique, 0xd280, 1)
	BOOL_NEGATE(unique + 0x24d80, 1, unique + 0xd380, 1); // (unique, 0x24d80, 1) BOOL_NEGATE (unique, 0xd380, 1)
	CBRANCH(ram + 0x10000e, 8, unique + 0x24d80, 1); //  ---  CBRANCH (ram, 0x10000e, 8) , (unique, 0x24d80, 1)
	COPY(reg + 0x0 /* RAX */, 8, reg + 0x30 /* RSI */, 8); // (register, 0x0, 8) COPY (register, 0x30, 8)
case 0x0010000e:
// RET
	LOAD(reg + 0x288 /* RIP */, 8, &(int64_t){0x1b1L}, 8, reg + 0x20 /* RSP */, 8); // (register, 0x288, 8) LOAD (const, 0x1b1, 8) , (register, 0x20, 8)
	INT_ADD(reg + 0x20 /* RSP */, 8, reg + 0x20 /* RSP */, 8, &(int64_t){0x8L}, 8); // (register, 0x20, 8) INT_ADD (register, 0x20, 8) , (const, 0x8, 8)
	RETURN(reg + 0x288 /* RIP */, 8); //  ---  RETURN (register, 0x288, 8)
default: assert(0);
}}}