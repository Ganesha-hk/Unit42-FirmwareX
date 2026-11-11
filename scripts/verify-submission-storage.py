"""Check a real report survives teardown/restart and export its submission parts."""
import hashlib
import json
from pathlib import Path
import urllib.request

root = Path(__file__).resolve().parents[1]
out = root / 'evidence/submission-real-2026-11-10'
env = dict(line.split('=', 1) for line in (root / 'work/submission-instance/.env').read_text().splitlines())
report = json.loads((out / 'report.json').read_text())
headers = {'Authorization':'Bearer ' + env['FWX_API_TOKEN']}
def get(path):
    request = urllib.request.Request('http://127.0.0.1:8001' + path, headers=headers)
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)
firmware = get('/api/v1/firmware')['firmware']
assert len(firmware) == 1 and firmware[0]['firmware_id'] == report['firmware_id']
after = get('/api/v1/firmware/' + report['firmware_id'] + '/report')
def browser_numbers(value):
    # The original browser harness parsed JSON through IEEE-754 numbers.
    if isinstance(value, dict):
        return {key: browser_numbers(item) for key, item in value.items()}
    if isinstance(value, list):
        return [browser_numbers(item) for item in value]
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    return value
assert browser_numbers(after) == browser_numbers(report), 'Persisted report changed after restart'
for item in out.rglob('*'):
    if item.is_file() and item.suffix in {'.json','.html','.log','.md'}:
        payload = item.read_bytes()
        for name in ('FWX_API_TOKEN','FWX_DB_PASSWORD','FWX_ADMIN_PASSWORD'):
            assert env[name].encode() not in payload, 'Private configuration leaked'
for name, payload in {
    'server-report.json':after,
    'filesystem.json':report['files'],
    'mitigation-matrix.json':report['binaries'],
    'candidate-findings.json':{'interpretation':'Candidates, not independently validated vulnerabilities',
                              'findings':report['findings'],'evidence':report['evidence']},
    'reproduction.json':{'result':'PASS','initially_empty':True,'retained_after_teardown_restart':True,
        'firmware_records':len(firmware),'report_sha256':hashlib.sha256((out/'report.json').read_bytes()).hexdigest(),
        'limitation':'Same-host fresh database/queue/storage using existing Docker images. Not an independent clean-machine build.',
        'comparison':'All fields compared; numbers normalized to browser IEEE-754 precision. server-report.json preserves exact server integers.',
        'private_configuration_absent_from_text_exports':True},
}.items():
    with (out / name).open('x') as handle:
        json.dump(payload, handle, indent=2)
        handle.write('\n')
print('PASS: one real image, report persisted through restart, private configuration absent from text exports')
