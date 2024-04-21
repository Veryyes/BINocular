#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int bar(int a, int b, int c)
{
    a = a*a;
    if (a < 5)
    {
        return a + b;
    }else{
        if (a%10 == 3)
        {
            return a*c;
        }else{
            return c;
        }
    }
}

char* foo(char* input, int len)
{
    int i;
    for(i = 0; i<len; i++)
    {
        if (input[i] == 'a')
        {
            input[i] = 'A';
        }
    }
    return input;
}

int main(int argc, char** argv)
{
    char* global_str = "i use arch btw";
    char* input;
    int len;
    if (argc < 2)
    {
        puts("Need at least 1 cmd arg");
        return 1;
    }

    input = argv[1];
    len = strlen(input);
    input = foo(input, len);

    printf("%s\n", input);
    return 0;
}