/* SPDX-License-Identifier: MIT */
ENTRY(_start)
PHDRS { text PT_LOAD FLAGS(5); }
SECTIONS {
 . = 0x40010000;
 .text : { *(.text*) } :text
 .rodata : { *(.rodata*) } :text
 .data : { *(.data*) } :text
 .bss : { *(.bss*) } :text
 /DISCARD/ : { *(.ARM.exidx*) *(.ARM.extab*) *(.comment*) *(.note*) }
}
