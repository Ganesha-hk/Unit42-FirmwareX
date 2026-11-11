"""Compile project-owned MIT fixtures; never execute targets on the host."""
import hashlib
import json
import subprocess
from pathlib import Path

base = Path('/fixtures')
subprocess.run(['gcc', '-static', '-O0', '-g', '-fno-pie', '-no-pie',
                '-fno-omit-frame-pointer', '-Wl,--build-id=none',
                '/sources/protocol-fuzz.c', '-o', str(base/'protocol-fuzz')], check=True)
path = base/'protocol-fuzz'
digest = hashlib.sha256(path.read_bytes()).hexdigest()
Path('/manifests/fuzz-controlled.json').write_text(json.dumps({digest: {
    'binary': 'protocol-fuzz', 'architecture': 'x86_64', 'sha256': digest}}, indent=2)+'\n')
print(json.dumps({'fixture': path.name, 'sha256': digest, 'license': 'MIT'}))
