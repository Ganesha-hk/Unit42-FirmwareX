"""Build a controlled bare-metal counter to verify actual QEMU save/restore."""
import hashlib
import json
import subprocess
from pathlib import Path

path = Path('/fixtures/snapshot-arm.elf')
subprocess.run(['arm-linux-gnueabi-gcc', '-march=armv7-a', '-nostdlib', '-static',
                '-fno-pie', '-fno-stack-protector', '-Wl,-T,/sources/boot-arm.ld',
                '-Wl,--build-id=none', '/sources/snapshot-arm.c', '-o', str(path)], check=True)
digest = hashlib.sha256(path.read_bytes()).hexdigest()
target = {'binary': path.name, 'architecture': 'ARM32', 'sha256': digest}
Path('/manifests/snapshot-controlled.json').write_text(json.dumps({digest: target}, indent=2)+'\n')
print(json.dumps({'fixture': path.name, 'sha256': digest, 'license': 'MIT'}))
