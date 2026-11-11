"""Check the client checkout and host prerequisites without exposing secrets."""
from pathlib import Path
import os
import platform
import shutil
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
errors = []
if platform.system() != 'Linux' or platform.machine() not in ('x86_64', 'AMD64'):
    errors.append('Use a Linux x86-64 host or Ubuntu x86-64 VM; other hosts are not validated.')
if hasattr(os, 'getuid') and os.getuid() == 0:
    errors.append('Run as a normal Docker-enabled user, not root.')
for filename in ('compose.yaml', 'alembic.ini', 'pyproject.toml', 'src/firmwarex/api.py',
                 'infra/init-db.sh', 'scripts/bootstrap.py', 'scripts/wait-ready.py'):
    if not (root / filename).is_file():
        errors.append('Missing checkout file: ' + filename)
for dockerfile in (root / 'infra/images').rglob('*Dockerfile'):
    for line in dockerfile.read_text().splitlines():
        if line.startswith('COPY '):
            for source in line.split()[1:-1]:
                if not (root / source).exists():
                    errors.append(f'{dockerfile.relative_to(root)} requires missing {source}')
if not shutil.which('docker'):
    errors.append('Install Docker Engine and the Compose v2 plugin.')
else:
    for args, message in [(['docker', 'compose', 'version'], 'Docker Compose v2 is unavailable.'),
                          (['docker', 'info'], 'Docker is unavailable or this user lacks permission.')]:
        try:
            result = subprocess.run(args, capture_output=True, timeout=20)
            if result.returncode:
                errors.append(message)
        except subprocess.TimeoutExpired:
            errors.append(message)
print('Checkout:', root)
print('Host:', platform.system(), platform.machine())
print('Free disk: %.1f GiB' % (shutil.disk_usage(root).free / 1024**3))
for error in errors:
    print('ERROR:', error)
if errors:
    sys.exit(1)
print('Prerequisites and Docker build inputs are present. Network downloads and runtime checks follow during startup.')
