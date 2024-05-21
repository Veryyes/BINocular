#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int fib(int x)
{
    if (x==0)
        return 0;

    if (x==1)
        return 1;

    return fib(x-1) + fib(x-2);
}

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        return 1;
    }

    int a;
    a = atoi(argv[1]);
    printf("fib (%d) = %d\n", a, fib(a));
}