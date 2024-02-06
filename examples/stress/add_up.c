#include "../../templates/_pcode.h"
// #include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
int main()
{
    uint64_t x;
    x = x % 50;
    uint64_t y = 0;
    uint64_t one = 1;
    uint64_t old_x = x;
    while (x > 0)
    {
        INT_ADD(&y, 8, &y, 8, &one, 8);
        INT_SUB(&x, 8, &x, 8, &one, 8);
    }
    assert(y == old_x);
    assert(y == old_x + 1);
    printf("Values x %d y %d ", old_x, y);
}