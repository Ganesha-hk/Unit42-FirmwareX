/* SPDX-License-Identifier: MIT. Controlled errno and empty-standard-input regression. */
#include <errno.h>
#include <unistd.h>

int main(void) {
    char buffer[4];
    errno = 22;
    if (read(0, buffer, sizeof(buffer)) != 0) return 1;
    return errno == 22 ? 0 : 1;
}
