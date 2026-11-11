#!/bin/sh
set -eu
mkdir -p /fixtures/analysis
for source in 0 1 2 3; do
 for sink in 0 1 2 3 4 5; do
  gcc -g -gdwarf-4 -O0 -fno-omit-frame-pointer -fno-builtin -fno-stack-protector -no-pie -DSOURCE=$source -DSINK=$sink /sources/symbolic.c -o /fixtures/analysis/source${source}-sink${sink}
 done
done
for variant in negative unreachable; do
 flag=$(echo "$variant" | tr '[:lower:]' '[:upper:]')
 gcc -g -gdwarf-4 -O0 -fno-omit-frame-pointer -fno-builtin -no-pie -D$flag /sources/symbolic.c -o /fixtures/analysis/$variant
done
for region in 1 2 3; do
 gcc -g -gdwarf-4 -O0 -fno-omit-frame-pointer -fno-builtin -fno-stack-protector -no-pie -DREGION=$region /sources/symbolic.c -o /fixtures/analysis/region$region
done
for variant in fault loop branch; do
 flag=$(echo "$variant" | tr '[:lower:]' '[:upper:]')
 gcc -g -gdwarf-4 -O0 -fno-omit-frame-pointer -fno-builtin -no-pie -D$flag /sources/symbolic-budget.c -o /fixtures/analysis/$variant
done
for pair in mips:mips-linux-gnu-gcc mipsel:mipsel-linux-gnu-gcc arm:arm-linux-gnueabi-gcc aarch64:aarch64-linux-gnu-gcc; do
 name=${pair%%:*}; compiler=${pair#*:}
 "$compiler" -g -gdwarf-4 -O0 -fno-builtin -no-pie -DSOURCE=1 -DSINK=3 /sources/symbolic.c -o /fixtures/analysis/cross-$name
done

python - <<'BUILD_SCANNER'
from pathlib import Path
Path('/fixtures/analysis/scanner.txt').write_bytes(b'password=UnitTestPassword123\napi_key=Q7vM2xL9pR4nB8cK3sD6fH1j\n-----BEGIN PRIVATE KEY-----\nSYNTHETIC-NOT-A-REAL-KEY\n-----END PRIVATE KEY-----\n-----BEGIN CERTIFICATE-----\nSYNTHETIC-CERTIFICATE\n-----END CERTIFICATE-----\nauthentication_hash=md5\nlegacy_cipher=rc4\nblob=H5nZ2wC8qR4mA7vJ3xL9tB6k\n')
BUILD_SCANNER

gcc -g -gdwarf-4 -O0 -fno-omit-frame-pointer -fno-builtin -fno-stack-protector -no-pie -DCHAIN -DSINK=3 /sources/symbolic.c -o /fixtures/analysis/chain
gcc -g -gdwarf-4 -O0 -fno-omit-frame-pointer -fno-builtin -fno-stack-protector -no-pie -DEXTRA=3 /sources/symbolic-allocation.c -o /fixtures/analysis/allocation-safe
gcc -g -gdwarf-4 -O0 -fno-omit-frame-pointer -fno-builtin -fno-stack-protector -no-pie -DEXTRA=2 /sources/symbolic-allocation.c -o /fixtures/analysis/allocation-unsafe
gcc -g -gdwarf-4 -O0 -fno-omit-frame-pointer -fno-builtin -fno-stack-protector -no-pie /sources/symbolic-allocation-budget.c -o /fixtures/analysis/allocation-truncated
gcc -g -gdwarf-4 -O0 -fno-omit-frame-pointer -fno-builtin -fno-stack-protector -no-pie /sources/symbolic-runtime-models.c -o /fixtures/analysis/runtime-models
as /sources/static-risk.s -o /tmp/static-risk.o
ld -N /tmp/static-risk.o -o /fixtures/static-risk
