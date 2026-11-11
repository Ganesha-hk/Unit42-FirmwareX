/* SPDX-License-Identifier: MIT. Controlled fixture; execute only in sandbox. */
#include <stdlib.h>
#include <string.h>
char destination[8];
int main(int argc, char **argv) {
    char *value = getenv("CONTENT_TYPE");
    if (argc != 1 || !argv || !argv[0] || getenv("ABSENT") != 0 ||
        !getenv("CONTENT_LENGTH") || strcmp(getenv("CONTENT_LENGTH"), "0") ||
        !value || value != getenv("CONTENT_TYPE")) {
        *(volatile int *)0 = 1;
        return 1;
    }
    if (value[0] == 'A') strcpy(destination, value);
    return 0;
}
