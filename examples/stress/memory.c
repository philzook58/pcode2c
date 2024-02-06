#include "../../templates/_pcode.h"
// #include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
int main()
{
    uint8_t *mem = malloc(0x100000);
    uint8_t temp;
    temp = temp + 42;
    mem[0] = temp;
    for (int i = 0; i < 99; i++)
    {
        COPY(mem + i + 1, 1, mem + i, 1);
        COPY(mem + i, 1, mem + i + 1, 1);
    }
    assert(mem[99] == temp);
    printf("Values mem[0] %d mem[99] %d ", mem[0], mem[99]);
    free(mem);
}