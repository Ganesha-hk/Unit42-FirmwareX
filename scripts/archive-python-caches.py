"""Recoverably remove Python caches from source/test/script trees only."""
import json
from pathlib import Path
import shutil

root = Path(__file__).resolve().parents[1]
archive = root / 'work/cache-archive-2026-11-10'
if archive.exists():
    raise SystemExit('Cache archive already exists; retained.')
targets = sorted(path for folder in ('src','tests','scripts')
                 for path in (root / folder).rglob('__pycache__')
                 if path.is_dir() and not path.is_symlink()
                 and path.resolve().is_relative_to(root))
rows = []
for source in targets:
    relative = source.relative_to(root)
    target = archive / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(source), str(target))
    rows.append({'source':str(relative), 'recoverable_at':str(target.relative_to(root))})
print(json.dumps({'action':'moved_python_caches','count':len(rows),'paths':rows}, indent=2))
