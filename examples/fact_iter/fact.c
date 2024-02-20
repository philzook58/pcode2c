/*
Some fun stuff to play with. Could take in unsigned int.
!= form is classic problem wth given negative argument.

*/

int fact(int x)
{
    // fun_entry:
    int result = 1;
loop_head:
    while (x != 0)
    {
    loop_body:
        result = result * x;
        x = x - 1;
    }
loop_exit:
    return result;
}