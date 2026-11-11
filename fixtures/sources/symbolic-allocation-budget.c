/* SPDX-License-Identifier: MIT. Controlled symbolic-allocation coverage regression. */
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *value = getenv("CONTENT_TYPE");
    if (!value) return 1;
    /* The modeled source constrains this byte to printable values, so both
       allocations at or below and above the analysis backing limit exist. */
    size_t size = (unsigned char)value[0];
    char *destination = malloc(size);
    if (!destination) return 1;
    memcpy(destination, value, 1);
    free(destination);
    return 0;
}
