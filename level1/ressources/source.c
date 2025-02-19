#include <stdio.h>
#include <stdlib.h>

int run()
{
  fwrite("Good... Wait what?\n", 1u, 0x13u, stdout);
  return system("/bin/sh");
}

int main(void)
{
  char s[64];
  return gets(s);
}