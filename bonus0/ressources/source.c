#include <string.h>
#include <stdint.h>

static char * p(char *dest, char *s)
{
  char buf[4096];

  puts(s);
  read(0, buf, 4096);
  *strchr(buf, 10) = 0;
  return strncpy(dest, buf, 20);
}

static char * pp(char *dest)
{
  char buff1[20];
  char buff2[20];

  p(buff1, " - ");
  p(buff2, " - ");
  strcpy(dest, buff1);
  *(uint16_t *)&dest[strlen(dest)] = 0x2000; // ' \0'
  return strcat(dest, buff2);
}

int main(void)
{
  char final_buff[42];

  pp(final_buff);
  puts(final_buff);
  return 0;
}