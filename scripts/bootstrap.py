"""Generate local secrets without printing them or changing host Python."""
from pathlib import Path
import os
import secrets

root = Path(__file__).resolve().parents[1]
env = root / ".env"
storage = root / ".runtime"
storage.mkdir(mode=0o700, exist_ok=True)
if env.exists():
    raise SystemExit(".env already exists; retained unchanged")
content = {
    "FWX_ADMIN_PASSWORD": secrets.token_hex(32),
    "FWX_DB_PASSWORD": secrets.token_hex(32),
    "FWX_API_TOKEN": secrets.token_hex(32),
    "FWX_COMPANY_REGISTRATION_CODE": secrets.token_urlsafe(32),
    "FWX_HOST_STORAGE": str(storage),
    "FWX_SANDBOX_UID": str(os.getuid()),
    "FWX_SANDBOX_GID": str(os.getgid()),
}
fd = os.open(env, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w") as f:
    f.write("".join(k + "=" + v + "\n" for k, v in content.items()))
print("Created private .env and .runtime; credentials were not printed.")
