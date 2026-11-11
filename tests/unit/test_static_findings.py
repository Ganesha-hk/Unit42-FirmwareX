from firmwarex.static_findings import leads
from firmwarex.persistence import safe_evidence
FIRMWARE='00000000-0000-4000-8000-000000000001'
def test_static_symbols_are_only_heuristic_leads():
 findings,evidence=leads([{'path':'/bin/secret-name','architecture':'x86_64','banned_functions':['strcpy','gets']}],FIRMWARE,b'unit-salt-32-bytes-long-for-test!!')
 assert {f['cwe'] for f in findings}=={'CWE-676','CWE-242'}
 for f in findings:
  assert f['confidence']=='heuristic' and f['risk_rating']=='low'
  assert f['address'] is None and f['crash_state']['overflow_offset'] is None
  assert 'secret-name' not in f['binary']
 for detail in evidence.values():
  safe_evidence(detail);assert not detail['invocation_proven'] and not detail['overflow_proven']
def test_unsupported_architecture_never_invents_schema_architecture():
 assert leads([{'path':'/bin/test','architecture':'unknown','banned_functions':['strcpy']}],FIRMWARE,b'unit-salt-32-bytes-long-for-test!!')==([], {})
