"""Cross-check delivered evidence; no target execution or network access."""
import json,xml.etree.ElementTree as ET
from pathlib import Path
from firmwarex.findings import validate
root=Path('/evidence');summary=json.loads((root/'summary.json').read_text())
unit=ET.parse(root/'unit-tests.xml').getroot().find('testsuite')
assert int(unit.attrib['tests'])==summary['unit_tests']==85
assert int(unit.attrib['errors'])==int(unit.attrib['failures'])==int(unit.attrib['skipped'])==0
report=json.loads((root/'controlled-report.json').read_text())
assert len(report['findings'])==summary['controlled_findings']==17
for finding in report['findings']:
 validate(finding);assert finding['evidence_ref'] in report['evidence']
result=report['jobs'][-1]['result'];spans=result['observability']['spans']+result['control_observability']['spans']
assert len(spans)==summary['lifecycle_spans']==11 and len({s['trace_id'] for s in spans})==1
assert len(json.loads((root/'lifecycle-failures.json').read_text()))==3
for name in ['browser-results.json','results.json']:assert json.loads((root/name).read_text())['passed']
rows=[line for line in Path('/docs/final-validation.md').read_text().splitlines() if line.startswith('FWX-')]
ids={row.split(' — ')[0] for row in rows};assert len(rows)==len(ids)==112
counts={'PASS':sum(' | PASS | ' in r for r in rows),'FAIL':sum(' | FAIL | ' in r for r in rows)}
assert counts==json.loads((root/'validation-counts.json').read_text())=={'PASS':78,'FAIL':34}
trace=[line for line in Path('/docs/requirements-traceability.md').read_text().splitlines() if line.startswith('FWX-')]
assert {row.split(' | ')[0] for row in trace}==ids
assert summary['real_firmware_execution']=='PENDING HUMAN REVIEW' and summary['safety_policy_blocked_operations']==[]
print('PASS: current unit, finding schema, trace, browser and all-112-requirement evidence consistency')
