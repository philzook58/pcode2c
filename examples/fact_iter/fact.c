/*
Some fun stuff to play with. Could take in unsigned int.
!= form is classic problem wth given negative argument.

*/

int fact(int x)
{
    int result = 1;
    while (x != 0)
    {
        result = result * x;
        x = x - 1;
    }
    return result;
}