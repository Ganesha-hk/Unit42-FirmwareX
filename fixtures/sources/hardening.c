/* Controlled, local-only hardening fixture. SPDX-License-Identifier: MIT */
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    char buffer[64] = {0};
    if (argc > 1) strcpy(buffer, argv[1]);
    puts(buffer);
    return 0;
}
