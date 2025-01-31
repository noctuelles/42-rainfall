# level2

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

Unlike *level2*, it does not have any existing code in the `.text` section to spawn a shell. In our exploit, we will have somehow to *add* additional code to spawn it. This is what we call a **shell code**.

In function `p`, the very unsafe `gets` get called again. Great, that is an wide open door for a **buffer overflow** : that means we can overwrite the return address of function `p` on the stack. But where should we return to ?

Remember when i talked about adding additional code. We can add this code in the initial buffer that `gets` uses, and modify the return address to point into our additional code that is located into the stack.

But there may be a problem using this technique in this particular setup, take a look at this snippet of instructions:

```
 80484f2:       8b 45 04                mov    eax,DWORD PTR [ebp+0x4] <---
 80484f5:       89 45 f4                mov    DWORD PTR [ebp-0xc],eax
 80484f8:       8b 45 f4                mov    eax,DWORD PTR [ebp-0xc]
 80484fb:       25 00 00 00 b0          and    eax,0xb0000000
 8048500:       3d 00 00 00 b0          cmp    eax,0xb0000000
 8048505:       75 20                   jne    8048527 <p+0x53>
```

It performs a check on the return address `ebp + 0x4` !  Basically, it checks if the most significant byte of the return address is `0xb`, which would mean that we manipulated it so it points on the stack. This would prevent us from correctly redirecting the execution flow into our shellcode. If this check doesn´t pass, we jump to `0x8048527` :

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

It echoes back when we just wrote into the buffer, and then proceed to duplicate the stack-allocated buffer into an heap-allocated region. Interesting ! So instead of modifying our return address so it points on our buffer that is allocated into the stack, we could modify it so it points into the heap-allocated region instead ! It will contains exactly the same data as it is duplicated.

The challange here is that our shell code must not include any NUL byte (`0x00`), since it will end prematurely `strdup` (remember that a C string is always nul-terminated).