#include "pcode.h"

int main()
{
    uint32_t x;
    uint64_t y = 0;
    y = x;
    uint8_t out1;
    uint8_t out2;
    POPCOUNT(&out1, 1, &x, 4);
    POPCOUNT(&out2, 1, &y, 8);
    assert(out1 == out2);

    y = 0;
    y |= ((uint64_t)x << 32);
    POPCOUNT(&out1, 1, &x, 4);
    POPCOUNT(&out2, 1, &y, 8);
    assert(out1 == out2);
    return 0;
}