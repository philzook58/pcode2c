#include <stdint.h>
typedef struct
{
    uint8_t dat[8];
} my_data;

my_data buffer[32];
extern int count;
void enqueue(my_data *data)
{
    count++;
    buffer[count] = *data;
}

my_data *dequeue()
{
    count--;
    return &buffer[count + 1];
}