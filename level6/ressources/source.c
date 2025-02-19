#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int n()
{
  return system("/bin/cat /home/user/level7/.pass");
}

static int m()
{
  return puts("Nope");
}

int main(int argc, char **argv) {
    void *buffer = malloc(0x40);
    int (*fn)() = malloc(0x4);
    fn = m;
    strcpy(buffer, argv[1]);
    fn();
    return 0;
}