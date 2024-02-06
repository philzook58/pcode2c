#include "../../templates/_pcode.h"
// #include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

int main()
{

    uint8_t ram[100];
    uint64_t one = 1;
    uint64_t two = 2;
    ram[0] = 42;
    for (uint64_t i = 1; i < 100; i++)
    {
        STORE(0, 0, &i, 8, ram + i - 1, 1);
    }
    // STORE(0, 0, &two, 8, ram + 1, 1);
    assert(ram[99] == 42);
}