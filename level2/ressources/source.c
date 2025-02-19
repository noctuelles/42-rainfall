#include <stdio.h>
#include <stdlib.h>

static char *p()
{
  char buffer[64];
  const void *retaddr_ptr;
  unsigned int retaddr; /* The retaddr is the saved eip of the stack frame of p. */

  fflush(stdout);
  gets(buffer);
  if ((retaddr & 0xB0000000) == -1342177280 )
  {
    printf("(%p)\n", retaddr_ptr);
    exit(1);
  }
  puts(buffer);
  return strdup(buffer);
}

int main(void)
{
  return p();
}