#!/bin/sh
set -eu
mkdir -p /fixtures/formats
mkfs.cramfs /fixtures/rootfs /fixtures/formats/cramfs.bin
mkfs.jffs2 -r /fixtures/rootfs -o /fixtures/formats/jffs2.bin -e 0x20000 --pad=0x40000
mkfs.ubifs -r /fixtures/rootfs -o /fixtures/formats/ubifs.bin -m 2048 -e 126976 -c 64
(cd /fixtures/rootfs && find . -print | cpio -o -H newc > /fixtures/formats/cpio.bin)
truncate -s 16M /fixtures/formats/ext.bin
mke2fs -t ext4 -F -d /fixtures/rootfs /fixtures/formats/ext.bin
