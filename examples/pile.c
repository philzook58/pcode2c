// https://arxiv.org/pdf/2302.02384.pdf
int abs(int x)
{
    int y = x;
    if (x < 0)
    {
        y = -x;
    }
    return y;
}

int binsearch(int x)
{
    int a[16];
    signed low = 0, high = 16;

    while (low < high)
    {
        signed middle = low + ((high - low) >> 1);
        if (a[middle] < x)
            high = middle;
        else if (a[middle] > x)
            low = middle + 1;
        else // a[middle]==x
            return middle;
    }

    return -1;
}

#include <stdio.h>

int main(int argc, char **argv)
{
    char password[8] = {'s', 'e', 'c', 'r', 'e', 't', '!', '\0'};
    char buffer[16] = {
        '\0',
    };
    int tmp;
    int index = 0;
    printf("Enter your name: ");
    while ((tmp = getchar()) != '\n')
    {
        buffer[index] = tmp;
        ++index;
    }

    printf("%s\n", buffer);

    return 0;
}