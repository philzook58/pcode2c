// https://fossies.org/linux/ghidra/GhidraDocs/languages/html/pcoderef.html

#include <string.h>
#include <stdint.h>
#include <assert.h>

#ifdef __CPROVER__
#define pcode2c_printf(...) __CPROVER_printf(__VA_ARGS__)
#else
#include <stdio.h>
#define pcode2c_printf(...) printf(__VA_ARGS__)
#endif

// Should I just have an array of pointers to more direclty reflect ghidra?
// Ghidra makes assumptions about PC being automatically updated (I think) that I am not covering
typedef struct CPUState
{
    uint8_t *reg, *unique, *ram;
    size_t pc;
} CPUState;

// Using macro rather than loop so not to pay unwinding cost in BMC
#define PRINTREG(N)                               \
    {                                             \
        memmove(&temp, state->reg + 8 * N, 8);    \
        pcode2c_printf("\tR" #N ": %lu\t", temp); \
    }

#define INSN(addr, insn)                                \
    {                                                   \
        state->pc = addr;                               \
        uint64_t temp;                                  \
        PRINTREG(0);                                    \
        PRINTREG(1);                                    \
        PRINTREG(2);                                    \
        PRINTREG(3);                                    \
        PRINTREG(4);                                    \
        PRINTREG(5);                                    \
        PRINTREG(6);                                    \
        PRINTREG(7);                                    \
        PRINTREG(8);                                    \
        PRINTREG(9);                                    \
        PRINTREG(10);                                   \
        pcode2c_printf("\n");                           \
        if (breakpoint == addr)                         \
        {                                               \
            pcode2c_printf("BREAKPOINT 0x%lu\n", addr); \
            fflush(0);                                  \
            return;                                     \
        }                                               \
        pcode2c_printf("0x%lu: %s\n", addr, insn);      \
    }

void COPY(uint8_t *out_addr, size_t out_size, uint8_t *in_addr, size_t in_size)
{
    pcode2c_printf("COPY: %p %lu %p %lu\n", out_addr, out_size, in_addr, in_size);
    assert(out_size == in_size);
    memmove(out_addr, in_addr, in_size);
}

// TODO. It is very worrying that I'm just ignoring the address space input0
// Yea. This can't possibly work as is.
// Macro it to use ram? Or actually use a space array
// TODO, once I separate out the address space from the offset, go back to function
/*
void LOAD(void *output_addr, size_t output_size, void *input0_addr, size_t input0_size, void *input1_addr, size_t input1_size)
{
    void *temp;
    pcode2c_printf("LOAD: %p %lu %p %lu %p %lu\n", output_addr, output_size, input0_addr, input0_size, input1_addr, input1_size);
    memmove(&temp, input1_addr, input1_size);
    pcode2c_printf("fllksjdklfjklsdfklskfjloo");
    fflush(0);
    memmove(output_addr, temp, output_size);
} */

// Hack.
#define LOAD(output_addr, output_size, input0_addr, input0_size, input1_addr, input1_size)                                            \
    {                                                                                                                                 \
        size_t temp;                                                                                                                  \
        pcode2c_printf("LOAD: %p %lu %p %lu %p %lu\n", output_addr, output_size, input0_addr, input0_size, input1_addr, input1_size); \
        memmove(&temp, input1_addr, input1_size);                                                                                     \
        pcode2c_printf("temp: %lu\n", temp);                                                                                          \
        fflush(0);                                                                                                                    \
        memmove(output_addr, ram + temp, output_size);                                                                                \
    }

/* An Indirect Store. Input 1 holds a pointer. Then temp holds an offset in ram */
#define STORE(input0_addr, input0_size, input1_addr, input1_size, input2_addr, input2_size)                                            \
    {                                                                                                                                  \
        size_t temp;                                                                                                                   \
        pcode2c_printf("STORE: %p %lu %p %lu %p %lu\n", input0_addr, input0_size, input1_addr, input1_size, input2_addr, input2_size); \
        memmove(&temp, input1_addr, input1_size);                                                                                      \
        memmove(ram + temp, input2_addr, input2_size);                                                                                 \
    }

// ******************** Control Flow ********************

#define BRANCH(pc_addr, pc_size)                               \
    {                                                          \
        pcode2c_printf("BRANCH: %lu %lu\n", pc_addr, pc_size); \
        assert(pc_size == 8);                                  \
        state->pc = pc_addr - ram;                             \
        break;                                                 \
    }

#define BRANCH_GOTO_TEMPFIX(pc_space, pc_addr, pc_size)        \
    {                                                          \
        pcode2c_printf("BRANCH: %s %lu\n", #pc_addr, pc_size); \
        goto L_##pc_addr;                                      \
    }

#define CBRANCH(pc_addr, pc_size, cond_addr, cond_size)                                       \
    {                                                                                         \
        pcode2c_printf("CBRANCH: %lu %lu %lu %lu\n", cond_addr, cond_size, pc_addr, pc_size); \
        uint8_t cond;                                                                         \
        assert(pc_size == 8);                                                                 \
        assert(cond_size == 1);                                                               \
        memmove(&cond, cond_addr, 1);                                                         \
        if (cond != 0)                                                                        \
        {                                                                                     \
            pcode2c_printf("BRANCH TAKEN\n");                                                 \
            state->pc = pc_addr - ram;                                                        \
            break;                                                                            \
        }                                                                                     \
    }

// TODO: i removed the pc updaste. is this ok?
//             state->pc = pc_addr;
// The subsequent update in INSN ought to work...

#define CBRANCH_GOTO_TEMPFIX(pc_space, pc_addr, pc_size, cond_space, cond_offset, cond_size)                 \
    {                                                                                                        \
        pcode2c_printf("CBRANCH_GOTO_TEMPFIX: %lu %lu %s %lu\n", cond_offset, cond_size, #pc_addr, pc_size); \
        uint8_t cond;                                                                                        \
        assert(pc_size == 8);                                                                                \
        assert(cond_size == 1);                                                                              \
        memmove(&cond, cond_space + cond_offset, 1);                                                         \
        if (cond != 0)                                                                                       \
        {                                                                                                    \
            pcode2c_printf("BRANCH TAKEN\n");                                                                \
            goto L_##pc_addr;                                                                                \
        }                                                                                                    \
    }

#define BRANCHIND(pc_addr, pc_size)                              \
    {                                                            \
        pcode2c_printf("BRANCHIND: %p %lu\n", pc_addr, pc_size); \
        assert(pc_size == 8);                                    \
        memmove(&(state->pc), pc_addr, 8);                       \
        break;                                                   \
    }

// TODO: is return reasonable here?
#define CALL(pc_addr, pc_size)                              \
    {                                                       \
        pcode2c_printf("CALL: %p %lu\n", pc_addr, pc_size); \
        assert(pc_size == 8);                               \
        state->pc = pc_addr - ram;                          \
        return;                                             \
    }

// TODO: is return reasonable here?
#define CALLIND(pc_addr, pc_size)                              \
    {                                                          \
        pcode2c_printf("CALLIND: %p %lu\n", pc_addr, pc_size); \
        assert(pc_size == 8);                                  \
        memmove(&(state->pc), pc_addr, 8);                     \
        return;                                                \
    }

// TODO: USERDEFINED

#define RETURN(pc_addr, pc_size)                              \
    {                                                         \
        pcode2c_printf("RETURN: %p %lu\n", pc_addr, pc_size); \
        assert(pc_size == 8);                                 \
        memmove(&(state->pc), pc_addr, 8);                    \
        return;                                               \
    }

//************  Arithmetic and Logic  ************

// TODO PIECE

void SUBPIECE(uint8_t *out_addr, size_t out_size, uint8_t *in_addr, size_t in_size, uint8_t *input1_addr, size_t input1_size)
{
    size_t offset;
    memmove(&offset, input1_addr, input1_size);
    size_t cpy_size = in_size - offset > out_size ? out_size : in_size - offset; // min
    memmove(out_addr, in_addr + offset, cpy_size);
}

// TODO: We can have something smaller. Unroll some kind of bit twiddling popcount.
// https://graphics.stanford.edu/~seander/bithacks.html#CountBitsSetNaive
/*
void POPCOUNT(void *out_addr, size_t out_size, void *in_addr, size_t in_size)
{
    pcode2c_printf("POPCOUNT: %p %lu %p %lu %p %lu\n", out_addr, out_size, in_addr, in_size); // https://graphics.stanford.edu/~seander/bithacks.html#CountBitsSetNaive
    assert(in_size <= 8);
    uint64_t v = 0; // count the number of bits set in v
    memmove(&v, in_addr, in_size);

    uint64_t c; // c accumulates the total bits set in v

    for (c = 0; v; v >>= 1)
    {
        c += v & 1;
    }
    memmove(out_addr, &c, out_size);
}
*/

// I don't want to be paying unwinding cost for this loop
void POPCOUNT(uint8_t *out_addr, size_t out_size, uint8_t *in_addr, size_t in_size)
{
    uint64_t v = 0;                              // count bits set in this (64-bit value)
    unsigned int c;                              // store the total here
    static const int S[] = {1, 2, 4, 8, 16, 32}; // Magic Binary Numbers
    static const uint64_t B[] = {0x5555555555555555, 0x3333333333333333,
                                 0x0F0F0F0F0F0F0F0F, 0x00FF00FF00FF00FF,
                                 0x0000FFFF0000FFFF, 0x00000000FFFFFFFF};

    pcode2c_printf("POPCOUNT: %p %lu %p %lu\n", out_addr, out_size, in_addr, in_size);
    assert(in_size <= 8);
    memmove(&v, in_addr, in_size);
    c = v - ((v >> 1) & B[0]);
    c = ((c >> S[1]) & B[1]) + (c & B[1]);
    c = ((c >> S[2]) + c) & B[2];
    c = ((c >> S[3]) + c) & B[3];
    c = ((c >> S[4]) + c) & B[4];
    c = ((c >> S[5]) + c) & B[5];
    memmove(out_addr, &c, out_size);
}

// TODO: LZCOUNT

void INT_EQUAL(uint8_t *out_addr, size_t out_size, uint8_t *in1_addr, size_t in1_size, uint8_t *in2_addr, size_t in2_size)
{
    pcode2c_printf("INT_EQUAL: %p %lu %p %lu %p %lu\n", out_addr, out_size, in1_addr, in1_size, in2_addr, in2_size);
    assert(in1_size == in2_size);
    assert(in1_size <= 8);
    uint8_t out;
    // We could use memcmp, but I don't want to pay the unwinding cost.
    // uint8_t out = memcmp(in1_addr, in2_addr, in1_size);
    // out = out == 0 ? 1 : 0;
    out = in1_addr[0] == in2_addr[0] && in1_addr[1] == in2_addr[1] && in1_addr[2] == in2_addr[2] && in1_addr[3] == in2_addr[3] && in1_addr[4] == in2_addr[4] && in1_addr[5] == in2_addr[5] && in1_addr[6] == in2_addr[6] && in1_addr[7] == in2_addr[7] ? 1 : 0;
    memmove(out_addr, &out, 1);
}

void INT_NOTEQUAL(uint8_t *out_addr, size_t out_size, uint8_t *in1_addr, size_t in1_size, uint8_t *in2_addr, size_t in2_size)
{

    pcode2c_printf("INT_NOTEQUAL: %p %lu %p %lu %p %lu\n", out_addr, out_size, in1_addr, in1_size, in2_addr, in2_size);
    assert(in1_size == in2_size);
    uint8_t out;
    assert(in1_size <= 8);
    out = in1_addr[0] == in2_addr[0] && in1_addr[1] == in2_addr[1] && in1_addr[2] == in2_addr[2] && in1_addr[3] == in2_addr[3] && in1_addr[4] == in2_addr[4] && in1_addr[5] == in2_addr[5] && in1_addr[6] == in2_addr[6] && in1_addr[7] == in2_addr[7] ? 0 : 1;
    memmove(out_addr, &out, 1);
}

#define IPRED(name, opexpr, sign)                                                                                         \
    void name(uint8_t *out_addr, size_t out_size, uint8_t *in0_addr, size_t in0_size, uint8_t *in1_addr, size_t in1_size) \
    {                                                                                                                     \
        pcode2c_printf(#name ": %p %lu %p %lu %p %lu\n", out_addr, out_size, in0_addr, in0_size, in1_addr, in1_size);     \
        assert(in0_size == in1_size);                                                                                     \
        assert(out_size == 1);                                                                                            \
        int8_t out;                                                                                                       \
        if (in0_size == 1)                                                                                                \
        {                                                                                                                 \
            sign##int8_t in0, in1, temp;                                                                                  \
            memmove(&in0, in0_addr, 1);                                                                                   \
            memmove(&in1, in1_addr, 1);                                                                                   \
            out = opexpr;                                                                                                 \
            memmove(out_addr, &out, 1);                                                                                   \
        }                                                                                                                 \
        else if (in0_size == 2)                                                                                           \
        {                                                                                                                 \
            sign##int16_t in0, in1, temp;                                                                                 \
            memmove(&in0, in0_addr, 2);                                                                                   \
            memmove(&in1, in1_addr, 2);                                                                                   \
            out = opexpr;                                                                                                 \
            memmove(out_addr, &out, 1);                                                                                   \
        }                                                                                                                 \
        else if (in0_size == 4)                                                                                           \
        {                                                                                                                 \
            sign##int32_t in0, in1, temp;                                                                                 \
            memmove(&in0, in0_addr, 4);                                                                                   \
            memmove(&in1, in1_addr, 4);                                                                                   \
            out = opexpr;                                                                                                 \
            memmove(out_addr, &out, 1);                                                                                   \
        }                                                                                                                 \
        else if (in0_size == 8)                                                                                           \
        {                                                                                                                 \
            sign##int64_t in0, in1, temp;                                                                                 \
            memmove(&in0, in0_addr, 8);                                                                                   \
            memmove(&in1, in1_addr, 8);                                                                                   \
            out = opexpr;                                                                                                 \
            memmove(out_addr, &out, 1);                                                                                   \
        }                                                                                                                 \
        else                                                                                                              \
        {                                                                                                                 \
            assert(in0_size == 1 || in0_size == 2 || in0_size == 4 || in0_size == 8);                                     \
        }                                                                                                                 \
    }

IPRED(INT_LESS, in0 < in1, u)
IPRED(INT_SLESS, in0 < in1, )
IPRED(INT_LESS_EQUAL, in0 <= in1, u)
IPRED(INT_SLESS_EQUAL, in0 < in1, )

void INT_ZEXT(uint8_t *out_addr, size_t out_size, uint8_t *in1_addr, size_t in1_size)
{
    pcode2c_printf("INT_ZEXT: %p %lu %p %lu\n", out_addr, out_size, in1_addr, in1_size);
    assert(out_size > in1_size);
    uint8_t out[out_size];
    memset(out, 0, out_size);
    memmove(out, in1_addr, in1_size);
    memmove(out_addr, out, out_size);
}

void INT_SEXT(uint8_t *out_addr, size_t out_size, uint8_t *in1_addr, size_t in1_size)
{
    pcode2c_printf("INT_SEXT: %p %lu %p %lu\n", out_addr, out_size, in1_addr, in1_size);
    assert(out_size > in1_size);
    // https://graphics.stanford.edu/~seander/bithacks.html#VariableSignExtend
    unsigned b = out_size * 8; // number of bits representing the number in x
    int64_t x = 0;             // sign extend this b-bit number to r
    int64_t r;                 // resulting sign-extended number
    int64_t m = 1U << (b - 1); // mask can be pre-computed if b is fixed

    memmove(&x, in1_addr, in1_size);

    // x = x & ((1U << b) - 1); // (Skip this if bits in x above position b are already zero.)
    r = (x ^ m) - m;
    memmove(out_addr, &r, out_size);
}

#define IBINOP_PRECOND(name, op, precond)                                                                                     \
    void name(uint8_t *out_addr, size_t out_size, uint8_t *in1_addr, size_t in1_size, uint8_t *in2_addr, size_t in2_size)     \
    {                                                                                                                         \
        pcode2c_printf(#name ": %p %lu %p %lu %p %lu\n", (void *)out_addr, out_size, in1_addr, in1_size, in2_addr, in2_size); \
        assert(precond);                                                                                                      \
        if (out_size == 1)                                                                                                    \
        {                                                                                                                     \
            int8_t in1, in2, out;                                                                                             \
            memmove(&in1, in1_addr, out_size);                                                                                \
            memmove(&in2, in2_addr, out_size);                                                                                \
            out = in1 op in2;                                                                                                 \
            memmove(out_addr, &out, out_size);                                                                                \
        }                                                                                                                     \
        else if (out_size == 2)                                                                                               \
        {                                                                                                                     \
            int16_t in1, in2, out;                                                                                            \
            memmove(&in1, in1_addr, out_size);                                                                                \
            memmove(&in2, in2_addr, out_size);                                                                                \
            out = in1 op in2;                                                                                                 \
            memmove(out_addr, &out, out_size);                                                                                \
        }                                                                                                                     \
        else if (out_size == 4)                                                                                               \
        {                                                                                                                     \
            int32_t in1, in2, out;                                                                                            \
            memmove(&in1, in1_addr, out_size);                                                                                \
            memmove(&in2, in2_addr, out_size);                                                                                \
            out = in1 op in2;                                                                                                 \
            memmove(out_addr, &out, out_size);                                                                                \
        }                                                                                                                     \
        else if (out_size == 8)                                                                                               \
        {                                                                                                                     \
            int64_t in1, in2, out;                                                                                            \
            memmove(&in1, in1_addr, out_size);                                                                                \
            memmove(&in2, in2_addr, out_size);                                                                                \
            out = in1 op in2;                                                                                                 \
            memmove(out_addr, &out, out_size);                                                                                \
        }                                                                                                                     \
        else                                                                                                                  \
        {                                                                                                                     \
            assert(out_size == 1 || out_size == 2 || out_size == 4 || out_size == 8);                                         \
        }                                                                                                                     \
    }

#define IBINOP(name, op) IBINOP_PRECOND(name, op, out_size == in1_size && out_size == in2_size)
IBINOP(INT_ADD, +)
IBINOP(INT_SUB, -)

#ifdef __CPROVER__
// https://diffblue.github.io/cbmc/cprover-manual/md_api.html
IPRED(INT_CARRY, __CPROVER_overflow_plus(in0, in1), u)
IPRED(INT_SCARRY, __CPROVER_overflow_plus(in0, in1), )
IPRED(INT_SBORROW, __CPROVER_overflow_minus(in0, in1), )
#else
// Use _p?
IPRED(INT_CARRY, __builtin_add_overflow(in0, in1, &temp), u)
IPRED(INT_SCARRY, __builtin_add_overflow(in0, in1, &temp), )
IPRED(INT_SBORROW, __builtin_sub_overflow(in0, in1, &temp), )
#endif

// TODO INT_2COMP
// TODO INT_NEGATE

IBINOP(INT_XOR, ^)
IBINOP(INT_AND, &)
IBINOP(INT_OR, |)

IBINOP_PRECOND(INT_LEFT, <<, out_size == in1_size)
// TODO: This is wrong it needs to be unsigned shift
IBINOP_PRECOND(INT_RIGHT, >>, out_size == in1_size)
IBINOP_PRECOND(INT_SRIGHT, >>, out_size == in1_size)
IBINOP(INT_MULT, *)
IBINOP(INT_DIV, /) // TODO: These should be unsigned
IBINOP(INT_REM, %)
// TODO: INT_SDIV
// TODO: INT_SREM

void BOOL_NEGATE(uint8_t *output_addr, size_t output_size, uint8_t *input_addr, size_t input_size)
{
    assert(output_size == 1 && input_size == 1);
    uint8_t in;
    memmove(&in, input_addr, 1);
    uint8_t out = !in;
    memmove(output_addr, &out, 1);
}

#define BOOL_BINOP(name, op)                                                                                                            \
    void name(uint8_t *output_addr, size_t output_size,                                                                                 \
              uint8_t *input0_addr, size_t input0_size,                                                                                 \
              uint8_t *input1_addr, size_t input1_size)                                                                                 \
    {                                                                                                                                   \
        pcode2c_printf(#name ": %p %lu %p %lu %p %lu\n", output_addr, output_size, input0_addr, input0_size, input1_addr, input1_size); \
        assert(output_size == 1 && input0_size == 1 && input1_size == 1);                                                               \
        uint8_t in0, in1;                                                                                                               \
        memmove(&in0, input0_addr, 1);                                                                                                  \
        memmove(&in1, input1_addr, 1);                                                                                                  \
        uint8_t out = in0 op in1;                                                                                                       \
        memmove(output_addr, &out, 1);                                                                                                  \
    }

BOOL_BINOP(BOOL_XOR, ^) // Hmm. Is using this XOR ok?
BOOL_BINOP(BOOL_AND, &&)
BOOL_BINOP(BOOL_OR, ||)

// TODO FLOAT ops

/*
#define BINOP(name, op, size, type)                                                                              \
    void name(void *out_addr, size_t out_size, void *in1_addr, size_t in1_size, void *in2_addr, size_t in2_size) \
    {                                                                                                            \
        type in1, in2, out;                                                                                      \
        memmove(&in1, in1_addr, size);                                                                            \
        memmove(&in2, in2_addr, size);                                                                            \
        out = in1 op in2;                                                                                        \
        memmove(out_addr, &out, size);                                                                            \
    }

#define IBINOP_SIZE(name, op, size) BINOP(name, op, size, int##size##_t)
#define UBINOP_SIZE(name, op, size) BINOP(name, op, size, uint##size##_t)

#define IBINOP(name, op)          \
    IBINOP_SIZE(name##8, op, 8)   \
    IBINOP_SIZE(name##16, op, 16) \
    IBINOP_SIZE(name##32, op, 32) \
    IBINOP_SIZE(name##64, op, 64)

#define UBINOP(name, op)          \
    UBINOP_SIZE(name##8, op, 8)   \
    UBINOP_SIZE(name##16, op, 16) \
    UBINOP_SIZE(name##32, op, 32) \
    UBINOP_SIZE(name##64, op, 64)

#define FBINOP(name, op) BINOP(name##32, op, 32, float) BINOP(name##64, op, 64, double)

*/
// IUNOP(INT_NEGATE, -)
// IUNOP(INT_NOT, ~)

/*
FBINOP(FLOAT_ADD, +)
FBINOP(FLOAT_SUB, -)
FBINOP(FLOAT_MUL, *)
*/
