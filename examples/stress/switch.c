#include "../../templates/_pcode.h"
// #include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

int main()
{
    uint64_t x;
    x = x % 26;
    while (1)
    {
        switch (x)
        {
        case 42:
            assert(x != 42);
        case 13:
            x += 6;
        case 16:
            x += 3;
            break;
        case 2:
            x += 1;
            break;
        case 2:
            x += 1;
            break;
        case 2:
            x += 1;
            break;
        case 2:
            x += 1;
            break;
        case 2:
            x += 1;
            break;
        case 2:
            x += 1;
            break;
        case 2:
            x += 1;
            break;
        case 2:
            x += 1;
            break;
        case 2:
            x += 1;
            break;
        case 2:
            x += 1;
            break;
        case 26:
            return 3;
        default:
            x += 1;
            break;
        }
    }
}