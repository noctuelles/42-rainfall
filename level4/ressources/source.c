#include <stdio.h>
#include <stdlib.h>

static int m = 0;

static int p(char *format)
{
    return printf(format);
}

static int n()
{
    int result;
    char buffer[512];

    fgets(buffer, 512, stdin);
    p(buffer);
    result = m;
    if (m == 16930116)
        return system("/bin/cat /home/user/level5/.pass");
    return result;
}

int main(void)
{
    return n();
}