import hashlib
import os
import stat
from pathlib import Path
from firmwarex.static import audit_elf

def inventory(root: Path, max_files=100000, max_bytes=512 * 1024 * 1024):
    entries, binaries, errors = [], [], []
    total = 0
    for parent, dirs, files in os.walk(root, followlinks=False):
        for name in sorted(dirs + files):
            path = Path(parent) / name
            info = path.lstat()
            mode = info.st_mode
            kind = "symlink" if stat.S_ISLNK(mode) else "directory" if stat.S_ISDIR(mode) else "file" if stat.S_ISREG(mode) else "special"
            relative = "/" + path.relative_to(root).as_posix()
            entry = {"path": relative, "type": kind, "size": info.st_size, "hash": None}
            if len(entries) >= max_files:
                raise ValueError("file_count_limit")
            if kind == "file":
                total += info.st_size
                if total > max_bytes:
                    raise ValueError("expanded_size_limit")
                digest = hashlib.sha256()
                with path.open("rb") as f:
                    for block in iter(lambda: f.read(1024 * 1024), b""):
                        digest.update(block)
                entry["hash"] = digest.hexdigest()
                try:
                    result = audit_elf(path, root)
                    if result:
                        binaries.append(result)
                except Exception:
                    errors.append({"path": relative, "code": "malformed_elf"})
            elif kind == "symlink":
                # Hash link text, never follow links out of reconstructed root.
                entry["hash"] = hashlib.sha256(os.readlink(path).encode("utf-8", errors="surrogateescape")).hexdigest()
            entries.append(entry)
    return sorted(entries, key=lambda e: e["path"]), sorted(binaries, key=lambda e: e["path"]), errors
