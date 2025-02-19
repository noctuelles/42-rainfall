#include <stdio.h>
#include <stdlib.h>

int main(int argc, const char **argv)
{
  char buffer[132];
  FILE *fp;

  fp = fopen("/home/user/end/.pass", "r");
  memset(buffer, 0, sizeof(buffer));
  if ( !fp || argc != 2 )
    return -1;
  fread(buffer, 1u, 0x42u, fp);
  buffer[65] = 0;
  buffer[atoi(argv[1])] = 0;
  fread(&buffer[66], 1u, 0x41u, fp);
  fclose(fp);
  if ( strcmp(buffer, argv[1]) == 0 )
    execl("/bin/sh", "sh", 0);
  else
    puts(&buffer[66]);
  return 0;
}