# level0

The program `level0` segfaults without any arguments.

An inspection under `gdb` reveals that the program is just performing a simple comparaison on the return value of the C library `atoi` function. The x86 64 `cmp` instruction with the hardcoded value `0x1a7` is used to branch on the shell, or print a simple `No !` message on the standard output.

After this analysis, feeding `423` to `level0` grants us access to the shell to retrieve the flag.