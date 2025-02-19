#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

static char c[68];

int main(int argc,char **argv)
{
  uint32_t *var1;
  void *tmp;
  uint32_t *var2;
  FILE *fp;
  
  var1 = malloc(8);
  var1[0] = 1;
  var1[1] = malloc(8);

  var2 = malloc(8);
  var2[0] = 2;
  var2[1] = malloc(8);

  strcpy((char *)var1[1],argv[1]);
  strcpy((char *)var2[1],argv[2]);

  fp = fopen("/home/user/level8/.pass","r");

  fgets(c,68,fp);
  puts("~~");

  return 0;
}