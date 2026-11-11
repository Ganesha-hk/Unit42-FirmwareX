"""Add a private company onboarding code without changing existing credentials."""
import argparse
import os
from pathlib import Path
import secrets

parser = argparse.ArgumentParser()
parser.add_argument('--env-file', type=Path, default=Path('.env'))
args = parser.parse_args()
path = args.env_file
if path.is_symlink() or not path.is_file():
    raise SystemExit('Expected an existing regular private environment file.')
content = path.read_text()
if any(line.startswith('FWX_COMPANY_REGISTRATION_CODE=') for line in content.splitlines()):
    raise SystemExit('Company code already configured; retained unchanged.')
path.chmod(0o600)
with path.open('a') as handle:
    if content and not content.endswith('\n'):
        handle.write('\n')
    handle.write('FWX_COMPANY_REGISTRATION_CODE=' + secrets.token_urlsafe(32) + '\n')
print('Company registration code added to the private configuration. No secrets printed.')
