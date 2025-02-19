#include <stdio.h>

static int m = 0;

static int v()
{
  int result;
  char s[512];

  fgets(s, 512, stdin);
  printf(s);
  result = m;
  if ( m == 64 )
  {
    fwrite("Wait what?!\n", 1u, 0xCu, stdout);
    return system("/bin/sh");
  }
  return result;
}

int main(void)
{
  return v();
}