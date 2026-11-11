/* SPDX-License-Identifier: MIT. Controlled RAM-state snapshot fixture. */
void boot_main(void) {
    volatile unsigned int *counter = (volatile unsigned int *)0x40020000;
    *counter = 0;
    for (;;) ++*counter;
}
__attribute__((naked)) void _start(void) {
    __asm__ volatile("ldr sp, =0x47fff000\nbl boot_main\nb .");
}
