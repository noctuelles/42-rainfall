#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>

int main(int argc,char **argv)
{
  int value;
  char *binsh;
  int useless;
  uid_t euid;
  gid_t egid;
  
  value = atoi(argv[1]);
  if (value == 423) {
    binsh = strdup("/bin/sh");
    useless = 0;
    egid = getegid();
    euid = geteuid();
    setresgid(egid,egid,egid);
    setresuid(euid,euid,euid);
    execv("/bin/sh",&binsh);
  }
  else {
    fwrite("No !\n",1,5,stderr);
  }
  return 0;
}