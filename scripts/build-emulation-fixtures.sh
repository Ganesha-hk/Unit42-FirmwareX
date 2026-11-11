#!/bin/sh
set -eu
mkdir -p /fixtures/emulation
for pair in mips:mips-linux-gnu-gcc mipsel:mipsel-linux-gnu-gcc arm:arm-linux-gnueabi-gcc aarch64:aarch64-linux-gnu-gcc x86_64:gcc; do
 name=${pair%%:*}
 compiler=${pair#*:}
 "$compiler" -static -O0 /sources/emulation.c -o "/fixtures/emulation/$name"
done
arm-linux-gnueabi-gcc -march=armv7-a -nostdlib -static -fno-pie -fno-stack-protector -Wl,-T,/sources/boot-arm.ld -Wl,--build-id=none /sources/boot-arm.c -o /fixtures/emulation/boot-arm.elf
arm-linux-gnueabi-gcc -static -O0 /sources/nvram-probe.c /sources/nvram-stub.c -o /fixtures/emulation/nvram-arm
