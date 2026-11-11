"""Execute controlled ground-truth cases against the current implementation.

This deliberately does not read a prior report.  Each row invokes the scanner,
static lead generator, or symbolic engine and checks the expected result.
"""
import json
from pathlib import Path
from uuid import uuid4

from firmwarex.analysis.engine import analyze
from firmwarex.scanners.secrets import scan
from firmwarex.static_findings import leads

salt = b'classification-ground-truth-salt-32b'
firmware_id = str(uuid4())
checks = []

def record(label, findings, expected, confidence, rationale):
    actual = {(f['cwe'], f['confidence']) for f in findings}
    assert actual == expected, (label, actual, expected)
    assert all(f['redacted'] for f in findings)
    checks.append({'label': label, 'expected': sorted(expected), 'actual': sorted(actual),
                   'confidence': confidence, 'result': 'pass', 'rationale': rationale})

static, _ = leads([{'path': '/bin/fixture', 'architecture': 'x86_64',
                    'banned_functions': ['strcpy']}], firmware_id, salt)
record('static symbol lead', static, {('CWE-676', 'heuristic')}, 'heuristic',
       'A symbol proves neither invocation nor overflow.')

credential = b'password=ControlledGroundTruth123'
result = scan(credential, firmware_id=firmware_id, path='/etc/config', architecture='MIPS', salt=salt)
record('credential assignment', result['findings'], {('CWE-259', 'probable')}, 'probable',
       'The controlled input contains an explicit password assignment.')
assert b'ControlledGroundTruth123'.decode() not in json.dumps(result)

weak = scan(b'authentication_hash=md5', firmware_id=firmware_id, path='/etc/config', architecture='MIPS', salt=salt)
record('weak crypto context', weak['findings'], {('CWE-328', 'heuristic')}, 'heuristic',
       'The controlled input has a security-related MD5 context; usage is not proven.')

root = Path('/fixtures/analysis')
if not root.is_dir():
    root = Path(__file__).resolve().parents[1] / 'work/fixtures/analysis'
for name, expected, confidence, rationale in [
    ('negative', set(), 'none', 'No controlled unsafe operation is present.'),
    ('fault', {('CWE-476', 'probable')}, 'probable', 'The fixture performs a null write.'),
    ('source0-sink0', {('CWE-787', 'probable')}, 'probable', 'The bounded symbolic source reaches an out-of-bounds copy.'),
]:
    report = analyze(root / name, firmware_id, '/bin/' + name, 'x86_64', salt)
    assert report['status'] == 'completed', report['reasons']
    record('symbolic ' + name, report['findings'], expected, confidence, rationale)

print(json.dumps({'status': 'passed', 'sample_size': len(checks), 'checks': checks,
                  'scope': 'Current controlled ground-truth execution. This validates the implemented rules, not a claim that arbitrary vendor firmware is exhaustively classified.'}, indent=2))
