"""Rerun the user's demo via the authenticated API; retain before/after evidence."""
import collections,json,time,urllib.request,os
from pathlib import Path
root=Path(__file__).resolve().parents[1]
env=dict(line.split('=',1) for line in (root/'.env').read_text().splitlines() if '=' in line)
headers={'Authorization':'Bearer '+env['FWX_API_TOKEN']}
out=root/os.environ.get('FWX_EVIDENCE_DIR','evidence/mentor-accuracy-2026-11-07');out.mkdir(parents=True,exist_ok=True)
def request(path,method='GET'):
    with urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:8000'+path,headers=headers,method=method),timeout=30) as response:return json.load(response)
items=request('/api/v1/firmware')['firmware'];old=next(i for i in items if i['display_name']==os.environ.get('FWX_ANALYSIS_NAME','demo'))
before=request('/api/v1/firmware/'+old['firmware_id']+'/report')
(out/'demo-before.json').write_text(json.dumps(before))
queued=request('/api/v1/firmware/'+old['firmware_id']+'/reanalyze','POST')
(out/'queued.json').write_text(json.dumps(queued))
end=time.monotonic()+210
while True:
    job=request('/api/v1/jobs/'+queued['job_id'])
    if job['status'] not in {'queued','running'}:break
    if time.monotonic()>end:raise TimeoutError('demo reanalysis')
    time.sleep(1)
after=request('/api/v1/firmware/'+queued['firmware_id']+'/report')
(out/'demo-after.json').write_text(json.dumps(after))
assert before['sha256']==after['sha256']
assert job['status'] in {'complete','partial'},job
stages=job['result']['stages']
assert stages['emulation']['authorization']=='mentor_authorized',stages
assert stages['symbolic']['authorization']=='mentor_authorized',stages
assert job['result']['sandbox']['network_mode']=='none'
assert before['findings']==request('/api/v1/firmware/'+old['firmware_id']+'/report')['findings']
def summary(report):
    return {'firmware_id':report['firmware_id'],'name':report['display_name'],'sha256':report['sha256'],'files':len(report['files']),'binaries':len(report['binaries']),'findings':len(report['findings']),'cwe':dict(collections.Counter(f['cwe'] for f in report['findings'])),'confidence':dict(collections.Counter(f['confidence'] for f in report['findings'])),'stages':report['jobs'][-1]['result']['stages']}
result={'before':summary(before),'after':summary(after),'sandbox':job['result']['sandbox'],'original_preserved':True}
(out/'comparison.json').write_text(json.dumps(result,indent=2))
print(json.dumps(result))
