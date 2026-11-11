#!/bin/sh
set -eu
mkdir -p /fixtures/cross
for arch in mips mipsel arm aarch64; do
    case "$arch" in
        arm) compiler=arm-linux-gnueabi-gcc ;;
        *) compiler=$arch-linux-gnu-gcc ;;
    esac
    "$compiler" -nostdlib -shared -fPIC /sources/cross.c -o "/fixtures/cross/$arch"
done
