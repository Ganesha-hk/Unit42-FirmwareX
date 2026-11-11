"""Create separate private credentials/storage for a clean real-image assessment."""
import os
from pathlib import Path
import secrets

root = Path(__file__).resolve().parents[1]
directory = root / 'work/submission-instance'
directory.mkdir(parents=True, exist_ok=True, mode=0o700)
env = directory / '.env'
storage = directory / 'storage'
if env.exists():
    raise SystemExit('Submission configuration exists; retained unchanged.')
storage.mkdir(mode=0o700)
values = {
    'FWX_ADMIN_PASSWORD': secrets.token_hex(32),
    'FWX_DB_PASSWORD': secrets.token_hex(32),
    'FWX_API_TOKEN': secrets.token_hex(32),
    'FWX_COMPANY_REGISTRATION_CODE': secrets.token_urlsafe(32),
    'FWX_HOST_STORAGE': str(storage),
    'FWX_SANDBOX_UID': str(os.getuid()),
    'FWX_SANDBOX_GID': str(os.getgid()),
    'FWX_HTTP_PORT': '8001',
    'FWX_MENTOR_AUTHORIZED_EXECUTION': 'true',
}
with os.fdopen(os.open(env, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as handle:
    handle.write(''.join(f'{key}={value}\n' for key, value in values.items()))
print('Created separate private submission configuration; no existing data changed.')
