"""Real symbolic regression cases; run only in the isolated analysis image."""
import json
from pathlib import Path
from uuid import uuid4
from firmwarex.analysis.engine import analyze
from firmwarex.analysis.budgets import Budgets
from firmwarex.output_policy import sanitize_output

salt = b'synthetic-symbolic-test-salt-32-bytes'
rows = []
for name, expected in [('negative', None), ('fault', 'CWE-476'), ('source0-sink0', 'CWE-787')]:
    result = analyze(Path('/fixtures/analysis') / name, str(uuid4()), '/bin/taint-demo', 'x86_64', salt)
    assert result['status'] == 'completed', result['reasons']
    if expected:
        assert len(result['findings']) == 1
        finding = result['findings'][0]
        assert finding['cwe'] == expected
        if name == 'fault':
            assert finding['crash_state']['fault_address'] == '0x0'
            assert finding['source'] is None
            assert result['evidence'][finding['evidence_ref']]['kind'] == 'symbolic_null_write'
        else:
            assert finding['source'] == 'fwx_cgi_stdin_0'
    else:
        assert not result['findings']
    rows.append({'case': name, 'expected_cwe': expected, 'result': sanitize_output(result, salt)})
for value in [float('nan'), float('inf'), True]:
    try:
        Budgets(seconds=value)
    except ValueError:
        continue
    raise AssertionError('invalid time accepted')
print(json.dumps({'passed': len(rows), 'cases': rows}, indent=2))
