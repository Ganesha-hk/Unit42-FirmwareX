/* SPDX-License-Identifier: MIT. Controlled symbolic allocation regression. */
#include <stdlib.h>
#include <string.h>

#ifndef EXTRA
#define EXTRA 3
#endif

int main(void) {
    char *value = getenv("CONTENT_TYPE");
    if (!value) return 1;
    char *destination = malloc(strlen(value) + EXTRA);
    if (!destination) return 1;
    strcpy(destination, "--");
    strcpy(destination + 2, value);
    free(destination);
    return 0;
}
