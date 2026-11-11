"""Audit declared input provenance and committed evidence for prohibited plaintext."""
import hashlib, json, re
from pathlib import Path

root = Path(__file__).resolve().parents[1]
manifests = sorted((root / 'fixtures/manifests').glob('*.json'))
licenses = []
for path in manifests:
    doc = json.loads(path.read_text())
    license_name = doc.get('license')
    assert isinstance(license_name, str) and license_name.strip(), path
    if 'openwrt' in path.name:
        assert doc.get('license_source') and doc.get('source') and doc.get('frozen_before_analysis') is True
    licenses.append({'manifest': str(path.relative_to(root)), 'license': license_name,
                     'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})

sentinels = [b'PipelineSecretSentinel123', b'PROPRIETARY-CONTENT-SENTINEL',
             b'proprietary-sentinel-private', b'UnitTestPassword123', b'SYNTHETIC-NOT-A-REAL-KEY']
scan_roots = [root / 'evidence', root / 'docs']
matches = []
for scan_root in scan_roots:
    for path in scan_root.rglob('*'):
        if not path.is_file() or path.stat().st_size > 64 * 1024 * 1024:
            continue
        data = path.read_bytes()
        for sentinel in sentinels:
            if sentinel in data:
                matches.append(str(path.relative_to(root)))
assert not matches, matches
print(json.dumps({'status': 'passed', 'manifests': licenses,
                  'evidence_roots': [str(p.relative_to(root)) for p in scan_roots],
                  'sentinel_matches': 0,
                  'scope': 'Declared fixture/OpenWrt provenance and committed documentation/evidence sentinel scan; not a proof about ignored private input storage or every future output.'}, indent=2))
