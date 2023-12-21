#include "pcode.h"
#include <stdint.h>
int main()
{
    uint8_t reg[128];
    uint8_t unique[2048]; // unique can actually be a local (?)

    INT_ADD16(reg, reg + 8, reg + 16);
    FLOAT_ADD16(reg, reg, reg);
}
