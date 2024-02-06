#include <stdio.h>

int test_fun(int n)
{
    int n, sum = 0;
    for (int i = 1; i <= n; ++i)
    {
        sum += i;
    }
    return sum;
}
