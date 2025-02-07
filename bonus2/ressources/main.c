#include <stdio.h>
#include <memory.h>
#include <string.h>
#include <stdlib.h>

int language = 0;

const char *NL = "Hyvää päivää ";
const char *FL = "";
const char *DFT = "";


void greeuser(char *ptr)
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
    strcat(ptr, buffer);
    puts(ptr);
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
