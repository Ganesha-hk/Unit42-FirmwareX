"""Validate recorded production findings against both published and runtime contracts.

This checks interchange consistency, not vulnerability truth or human review.
Run with an existing jsonschema installation and PYTHONPATH=src; no guest execution.
"""
import hashlib
import json
from pathlib import Path
from jsonschema import Draft202012Validator, FormatChecker
from firmwarex.findings import validate

root = Path(__file__).resolve().parents[1]
schema_path = root / 'schemas/finding-v1.schema.json'
schema = json.loads(schema_path.read_text())
Draft202012Validator.check_schema(schema)
validator = Draft202012Validator(schema, format_checker=FormatChecker())
base = root / 'evidence/mentor-accuracy-2026-11-07'
paths = [base / 'regression/controlled-report.json',
         base / 'extended-fuzz.json', base / 'extended-snapshots.json',
         base / 'openwrt-demo/report.json', *sorted((base / 'corpus').glob('real-image-*.json'))]
rows = []
categories = set()
for path in paths:
    report = json.loads(path.read_text())
    assert report['findings'], path.name
    assert report['redacted'] is True
    assert report['schema_version'] == '1.0.0', report['schema_version']
    ids = set()
    for finding in report['findings']:
        validator.validate(finding)
        validate(finding)
        assert finding['firmware_id'] == report['firmware_id']
        assert finding['vulnerability_id'] not in ids
        ids.add(finding['vulnerability_id'])
        categories.add(finding['category'])
        assert finding['evidence_ref'] in report['evidence']
    rows.append({'report': str(path.relative_to(root)), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                 'firmware_id': report['firmware_id'], 'findings': len(ids)})
assert len(rows) == 10
assert {'memory_corruption', 'hardcoded_secret', 'weak_crypto', 'command_injection'} <= categories
print(json.dumps({'status': 'passed', 'schema_id': schema['$id'],
                  'schema_sha256': hashlib.sha256(schema_path.read_bytes()).hexdigest(),
                  'reports': rows, 'findings_checked': sum(r['findings'] for r in rows),
                  'categories': sorted(categories),
                  'scope': 'Recorded report schema, runtime validator, identity, unique IDs and evidence-reference integrity; not classification calibration.'}, indent=2))
