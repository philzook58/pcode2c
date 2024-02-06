// #include "_pcode.h"
#include "decomp.c"
#include <assert.h>
#include <stdlib.h> // TODO
int test_fun(int n);
int main()
{
    int examples[] = {0}; //, -1, -2, 1, 2, 3, 4, 5, 64, 128, MININT, MININT + 1, MAXINT, MAXINT - 1};
    for (int i = 0; i < sizeof(examples) / sizeof(examples[0]); i++)
    {
        int x = examples[i];
        CPUState state;
        state.reg = malloc(0x2000);
        state.unique = malloc(0xfffful);
        memcpy(&(state.reg[RDI]), &x, sizeof(x));
        pcode2c(&state, -1);
        int res;
        memcpy(&res, &(state.reg[RAX]), sizeof(res));
        assert(res == test_fun(x));
    }
}