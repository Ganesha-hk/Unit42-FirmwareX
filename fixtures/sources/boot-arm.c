/* SPDX-License-Identifier: MIT. Controlled bare-metal UART boot probe only. */
void boot_main(void) {
 volatile unsigned int *uart=(volatile unsigned int *)0x09000000;
 const char *p="FWX controlled boot\n";
 while(*p)*uart=(unsigned char)*p++;
 for(;;)__asm__ volatile("wfi");
}

__attribute__((naked)) void _start(void) { __asm__ volatile("ldr sp, =0x47fff000\nbl boot_main\nb ."); }
