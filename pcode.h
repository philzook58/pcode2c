
#include <string.h>
#include <stdint.h>

void assert(int x, ...)
{
    return;
}

typedef struct CPUState
{
    uint8_t *reg, *unique, *ram;
    uint64_t pc;
} CPUState;
/*
#define BINOP64(name, operator) void name(out,in1,in2){ }
#define BINOP(name,op,type)  void name(out,in1,in2){ type in1, in2, out; memcpy(&in1, in1, sizeof(type));\
    memcpy(&in2, in2, sizeof(type)); \
    out = in1 operator in2; \
    memcpy(out, out, sizeof(type)); }

void INT_ADD64(a1,a2,a3){
    int64_t op1, op2, out;
    memcpy(&in1, a1, 64);
    memcpy(&in2, a2, 64);
    memcpy(out, &out, 64);
}

*/
void COPY(void *out_addr, size_t out_size, void *in_addr, size_t in_size)
{
    assert(out_size == in_size);
    memcpy(out_addr, in_addr, in_size);
}

// TODO. It is very worrying that I'm just ignoring the address space input0
// Yea. This can't possibly work as is.
// Macro it to use ram? Or actually use a space arrya
void LOAD(void *output_addr, size_t output_size, void *input0_addr, size_t input0_size, void *input1_addr, size_t input1_size)
{
    void *temp;
    memcpy(&temp, input1_addr, input1_size);
    memcpy(output_addr, temp, output_size);
}

/* An Indirect Store */
void STORE(void *input0_addr, size_t input0_size, void *input1_addr, size_t input1_size, void *input2_addr, size_t input2_size)
{
    void *temp;
    memcpy(&temp, input1_addr, input1_size);
    memcpy(temp, input2_addr, input2_size);
}
//  assert(out_size == in1_size && out_size == in2_size);
// void LOAD(void *out_addr, void *in_addr, int size);

void BOOL_NEGATE(void *output_addr, size_t output_size, void *input_addr, size_t input_size)
{
    assert(output_size == 1 && input_size == 1);
    uint8_t in;
    memcpy(&in, input_addr, 1);
    uint8_t out = !in;
    memcpy(output_addr, &out, 1);
}

#define BOOL_BINOP(name, op)                                              \
    void name(void *output_addr, size_t output_size,                      \
              void *input0_addr, size_t input0_size,                      \
              void *input1_addr, size_t input1_size)                      \
    {                                                                     \
        assert(output_size == 1 && input0_size == 1 && input1_size == 1); \
        uint8_t in0, in1;                                                 \
        memcpy(&in0, input0_addr, 1);                                     \
        memcpy(&in1, input1_addr, 1);                                     \
        uint8_t out = in0 op in1;                                         \
        memcpy(output_addr, &out, 1);                                     \
    }

BOOL_BINOP(BOOL_AND, &&)
BOOL_BINOP(BOOL_OR, ||)
BOOL_BINOP(BOOL_XOR, ^) // Hmm. Is using this XOR ok?

/*
#define BINOP(name, op, size, type)                                                                              \
    void name(void *out_addr, size_t out_size, void *in1_addr, size_t in1_size, void *in2_addr, size_t in2_size) \
    {                                                                                                            \
        type in1, in2, out;                                                                                      \
        memcpy(&in1, in1_addr, size);                                                                            \
        memcpy(&in2, in2_addr, size);                                                                            \
        out = in1 op in2;                                                                                        \
        memcpy(out_addr, &out, size);                                                                            \
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
#define IBINOP(name, op)                                                                                         \
    void name(void *out_addr, size_t out_size, void *in1_addr, size_t in1_size, void *in2_addr, size_t in2_size) \
    {                                                                                                            \
        assert(out_size == in1_size && out_size == in2_size);                                                    \
        if (out_size == 1)                                                                                       \
        {                                                                                                        \
            int8_t in1, in2, out;                                                                                \
            memcpy(&in1, in1_addr, out_size);                                                                    \
            memcpy(&in2, in2_addr, out_size);                                                                    \
            out = in1 op in2;                                                                                    \
            memcpy(out_addr, &out, out_size);                                                                    \
        }                                                                                                        \
        else if (out_size == 2)                                                                                  \
        {                                                                                                        \
            int16_t in1, in2, out;                                                                               \
            memcpy(&in1, in1_addr, out_size);                                                                    \
            memcpy(&in2, in2_addr, out_size);                                                                    \
            out = in1 op in2;                                                                                    \
            memcpy(out_addr, &out, out_size);                                                                    \
        }                                                                                                        \
        else if (out_size == 4)                                                                                  \
        {                                                                                                        \
            int32_t in1, in2, out;                                                                               \
            memcpy(&in1, in1_addr, out_size);                                                                    \
            memcpy(&in2, in2_addr, out_size);                                                                    \
            out = in1 op in2;                                                                                    \
            memcpy(out_addr, &out, out_size);                                                                    \
        }                                                                                                        \
        else if (out_size == 8)                                                                                  \
        {                                                                                                        \
            int64_t in1, in2, out;                                                                               \
            memcpy(&in1, in1_addr, out_size);                                                                    \
            memcpy(&in2, in2_addr, out_size);                                                                    \
            out = in1 op in2;                                                                                    \
            memcpy(out_addr, &out, out_size);                                                                    \
        }                                                                                                        \
        else                                                                                                     \
        {                                                                                                        \
            assert(0, "unsupported integer operation");                                                          \
        }                                                                                                        \
    }

IBINOP(INT_ADD, +)
IBINOP(INT_SUB, -)
IBINOP(INT_AND, &)
IBINOP(INT_OR, |)
IBINOP(INT_XOR, ^)
IBINOP(INT_REM, %)
IBINOP(INT_DIV, /)
IBINOP(INT_MULT, *)
IBINOP(INT_LEFT, <<)
IBINOP(INT_RIGHT, >>)

#define IPRED(name, op, sign)                                                                                    \
    void name(void *out_addr, size_t out_size, void *in0_addr, size_t in0_size, void *in1_addr, size_t in1_size) \
    {                                                                                                            \
        assert(out_size == in0_size && out_size == in1_size);                                                    \
        int8_t out;                                                                                              \
        if (out_size == 1)                                                                                       \
        {                                                                                                        \
            sign##int8_t in0, in1;                                                                               \
            memcpy(&in0, in0_addr, in0_size);                                                                    \
            memcpy(&in1, in1_addr, in1_size);                                                                    \
            out = in0 op in1;                                                                                    \
            memcpy(out_addr, &out, out_size);                                                                    \
        }                                                                                                        \
        else if (out_size == 2)                                                                                  \
        {                                                                                                        \
            sign##int16_t in0, in1;                                                                              \
            memcpy(&in0, in0_addr, in0_size);                                                                    \
            memcpy(&in1, in1_addr, in1_size);                                                                    \
            out = in0 op in1;                                                                                    \
            memcpy(out_addr, &out, out_size);                                                                    \
        }                                                                                                        \
        else if (out_size == 4)                                                                                  \
        {                                                                                                        \
            sign##int32_t in0, in1;                                                                              \
            memcpy(&in0, in0_addr, in0_size);                                                                    \
            memcpy(&in1, in1_addr, in1_size);                                                                    \
            out = in0 op in1;                                                                                    \
            memcpy(out_addr, &out, out_size);                                                                    \
        }                                                                                                        \
        else if (out_size == 8)                                                                                  \
        {                                                                                                        \
            sign##int64_t in0, in1;                                                                              \
            memcpy(&in0, in0_addr, in0_size);                                                                    \
            memcpy(&in1, in1_addr, in1_size);                                                                    \
            out = in0 op in1;                                                                                    \
            memcpy(out_addr, &out, out_size);                                                                    \
        }                                                                                                        \
        else                                                                                                     \
        {                                                                                                        \
            assert(0, "unsupported integer operation");                                                          \
        }                                                                                                        \
    }

IPRED(INT_LESS, <, u)
IPRED(INT_SLESS, <, )
IPRED(INT_LESS_EQUAL, <=, u)
IPRED(INT_SLESS_EQUAL, <, )

void INT_SBORROW(void *out_addr, size_t out_size, void *in1_addr, size_t in1_size, void *in2_addr, size_t in2_size)
{
    assert(in1_size == in2_size);
    // TODO
    // uint8_t out = 0;
    // memcpy(out_addr, &out, 1);
}

void INT_EQUAL(void *out_addr, size_t out_size, void *in1_addr, size_t in1_size, void *in2_addr, size_t in2_size)
{
    assert(in1_size == in2_size);
    uint8_t out = memcmp(in1_addr, in2_addr, in1_size);
    out = out == 0 ? 0 : 1;
    memcpy(out_addr, &out, 1);
}

void INT_NOTEQUAL(void *out_addr, size_t out_size, void *in1_addr, size_t in1_size, void *in2_addr, size_t in2_size)
{
    assert(in1_size == in2_size);
    uint8_t out = memcmp(in1_addr, in2_addr, in1_size);
    out = out == 0 ? 1 : 0;
    memcpy(out_addr, &out, 1);
}

void INT_ZEXT(void *out_addr, size_t out_size, void *in1_addr, size_t in1_size)
{
    assert(out_size > in1_size);
    uint8_t out[out_size];
    memset(out, 0, out_size);
    memcpy(out, in1_addr, in1_size);
    memcpy(out_addr, out, out_size);
}

void INT_SEXT(void *out_addr, size_t out_size, void *in1_addr, size_t in1_size)
{
    assert(out_size > in1_size);
    uint8_t out[out_size];
    memset(out, 0, out_size);
    memcpy(out, in1_addr, in1_size);
    memcpy(out_addr, out, out_size);
}

// IUNOP(INT_NEGATE, -)
// IUNOP(INT_NOT, ~)

/*
FBINOP(FLOAT_ADD, +)
FBINOP(FLOAT_SUB, -)
FBINOP(FLOAT_MUL, *)
*/

// TODO: We can have something smaller. Unroll some kind of bit twiddling popcount.
void POPCOUNT(void *out_addr, size_t out_size, void *in_addr, size_t in_size)
{
    // https://graphics.stanford.edu/~seander/bithacks.html#CountBitsSetNaive
    assert(in_size <= 8);
    uint64_t v = 0; // count the number of bits set in v
    memcpy(&v, in_addr, in_size);

    uint64_t c; // c accumulates the total bits set in v

    for (c = 0; v; v >>= 1)
    {
        c += v & 1;
    }
    memcpy(out_addr, &c, out_size);
}

void SUBPIECE(void *out_addr, size_t out_size, void *in_addr, size_t in_size, void *input1_addr, size_t input1_size)
{

    size_t offset;
    memcpy(&offset, input1_addr, input1_size);
    size_t cpy_size = in_size - offset > out_size ? out_size : in_size - offset; // min
    memcpy(out_addr, in_addr + offset, cpy_size);
}

// ******************** Control Flow ********************

#define BRANCH(pc_addr, pc_size)   \
    {                              \
        assert(pc_size == 8);      \
        state->pc = pc_addr - ram; \
        break;                     \
    }

// TODO: is return reasonable here?
#define CALL(pc_addr, pc_size)     \
    {                              \
        assert(pc_size == 8);      \
        state->pc = pc_addr - ram; \
        return;                    \
    }

#define CBRANCH(cond_addr, cond_size, pc_addr, pc_size) \
    {                                                   \
        uint8_t cond;                                   \
        assert(pc_size == 8);                           \
        assert(cond_size == 1);                         \
        memcpy(&cond, cond_addr, 8);                    \
        if (cond)                                       \
        {                                               \
            state->pc = pc_addr - ram;                  \
            break;                                      \
        }                                               \
    }

#define BRANCHIND(pc_addr, pc_size)       \
    {                                     \
        assert(pc_size == 8);             \
        memcpy(&(state->pc), pc_addr, 8); \
        break;                            \
    }

#define RETURN(pc_addr, pc_size)          \
    {                                     \
        assert(pc_size == 8);             \
        memcpy(&(state->pc), pc_addr, 8); \
        return;                           \
    }
