"""Assemble existing execution and redaction checks into an acceptance matrix."""
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
evidence = root / 'evidence'
latest = evidence / 'acceptance-2026-11-08'
hardening = evidence / 'hardening-2026-11-07'
mentor = evidence / 'mentor-accuracy-2026-11-07'

scopes = {}
for scope in ('static', 'emulation', 'analysis', 'pipeline'):
    rows = json.loads((latest / f'quotas-{scope}.json').read_text())
    modes = {row['mode']: row for row in rows}
    assert set(modes) == {'wall', 'cpu', 'memory', 'network'}
    assert all(row['cleanup_verified'] for row in rows)
    assert modes['wall']['result']['error_code'] == 'wall_quota'
    assert modes['cpu']['result']['error_code'] == 'cpu_quota'
    assert modes['memory']['result']['error_code'] == 'memory_quota'
    network = modes['network']['result']['checks']
    assert network['interfaces'] == ['lo'] and network['socket_present'] is False
    assert network['uid'] != 0 and network['mount_return'] == -1
    scopes[scope] = {'checks': sorted(modes), 'cleanup_verified': True,
                     'no_egress': True, 'non_root': True, 'quota_breaches_terminated': True}

output_rows = json.loads((hardening / 'output-quotas.json').read_text())
assert len(output_rows) == 5 and all(row['passed'] and row['cleanup_verified'] for row in output_rows)
contracts = json.loads((mentor / 'release-contracts.json').read_text())
assert contracts['status'] == 'passed' and contracts['findings_checked'] >= 179
provenance = json.loads((latest / 'provenance-redaction.json').read_text())
assert provenance['status'] == 'passed' and provenance['sentinel_matches'] == 0

coverage = {
    'status': 'passed_for_declared_implementation',
    'execution_paths': scopes,
    'output_paths': {
        'sandbox_artifact_size_inode_symlink_malformed_json': {'cases': len(output_rows), 'passed': True},
        'persisted_reports_schema_and_redacted': {'reports': len(contracts['reports']), 'findings': contracts['findings_checked'], 'passed': True},
        'committed_docs_and_evidence_sentinel_scan': {'passed': True},
    },
    'limitations': [
        'Evidence covers declared launch scopes and stored report paths, not hypothetical future code.',
        'The trusted dispatcher has Docker authority by design and is outside the untrusted job sandbox.',
        'Raw input storage is intentionally excluded from plaintext diagnostic-output assertions.'
    ]
}
print(json.dumps(coverage, indent=2))
