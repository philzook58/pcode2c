#include <assert.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
int add3(int x)
{
    return x + 3;
}

int add3_patch(int x)
{
    return x + 5;
}

// https://codeflaws.github.io/

int delete_if(int x)
{
    if (x == 0)
    {
        return 0;
    }
    return 1;
}
int delete_if_patch(int x)
{
    if (false)
    {
        return 0;
    }
    return 1;
}
int insert_if(int x)
{
    return 1;
}
int change_condition(int x)
{
    if (x >= 0)
    {
        return 0;
    }
    return 1;
}

int delete_assign(int x)
{
    x = x + 7;
    return x;
}

int swap_statement()
{
    printf("world");
    printf("hello");
}

int replace_const(int x)
{
    int buff[10];
    buff[0] = x;
    for (int i = 0; i < 10; i++)
    {
        buff[i] = buff[i - 1];
    }
    return buff[9];
}
/*
struct queue
{
    int buff[10];
    int head;
    int tail;
};

int enqueue(queue *buff)
{
    int buff[10];

    return x + 5;
}
*/
int main()
{
    assert(add3(3) == add3_patch(3));
    // assert()
}