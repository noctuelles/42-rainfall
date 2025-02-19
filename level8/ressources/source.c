#include <string.h>
#include <stdio.h>
#include <stdint.h>

static char *auth = NULL;
static char *service = NULL;

int main(void)
{
    char s[128];

    while (1)
    {
        printf("%p, %p \n", auth, (const void *)service);
        if (!fgets(s, 128, stdin))
            break;
        if (!memcmp(s, "auth ", 5))
        {
            auth = malloc(4u);
            *(uint32_t *)auth = 0;
            if (strlen(&s[5]) <= 30)
                strcpy(auth, &s[5]);
        }
        if (!memcmp(s, "reset", 5))
            free(auth);
        if (!memcmp(s, "service", 6))
            service = strdup(&s[8]);
        if (!memcmp(s, "login", 5))
        {
            if (auth[32])
                system("/bin/sh");
            else
                fwrite("Password:\n", 1u, 0xAu, stdout);
        }
    }
    return 0;
}