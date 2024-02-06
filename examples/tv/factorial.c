
int test_fun(int n)
{
    if (n == 0)
        return 1;
    else
        return (n * test_fun(n - 1));
}
