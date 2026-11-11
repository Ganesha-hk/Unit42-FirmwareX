"""Exercise optional stages through real upload, queue, persistence and API."""
import json
import time
import urllib.request
import uuid
from pathlib import Path

root=Path(__file__).resolve().parents[1]
env=dict(line.split('=',1) for line in (root/'.env').read_text().splitlines() if '=' in line)
headers={'Authorization':'Bearer '+env['FWX_API_TOKEN']}
out=root/'evidence/mentor-accuracy-2026-11-07'
def request(path,data=None,extra=None):
    with urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:8000'+path,data=data,headers={**headers,**(extra or {})}),timeout=30) as response:
        return json.load(response)

results=[]
for feature in ['fuzz','snapshots']:
    boundary='fwx'+uuid.uuid4().hex
    fields={'provenance_kind':'controlled_fixture','license_id':'MIT','display_name':'Verified '+feature+' pipeline'}
    parts=[(f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n{value}\r\n').encode() for key,value in fields.items()]
    parts.append((f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="fixture.bin"\r\nContent-Type: application/octet-stream\r\n\r\n').encode()+(root/'work/fixtures'/('controlled-extended-'+feature+'.bin')).read_bytes()+b'\r\n')
    parts.append(f'--{boundary}--\r\n'.encode())
    queued=request('/api/v1/firmware/upload',b''.join(parts),{'Content-Type':'multipart/form-data; boundary='+boundary})
    deadline=time.monotonic()+240
    while True:
        job=request('/api/v1/jobs/'+queued['job_id'])
        if job['status'] not in {'queued','running'}:break
        if time.monotonic()>deadline:raise TimeoutError(feature)
        time.sleep(1)
    report=request('/api/v1/firmware/'+queued['firmware_id']+'/report')
    (out/('extended-'+feature+'.json')).write_text(json.dumps(report,indent=2)+'\n')
    assert job['status']=='complete',job.get('result',{}).get('stages',job)
    stage=job['result']['stages'][feature]
    assert stage['status']=='completed',stage
    if feature=='fuzz':
        crashes=[f for f in report['findings'] if f['cwe']=='CWE-476']
        assert len(crashes)==1
        replays=report['evidence'][crashes[0]['evidence_ref']]['replays']
        assert {r['protocol'] for r in replays}=={'http','upnp','mqtt'}
        assert all(r['replay_verified'] for r in replays)
    else:
        assert stage['analyses'][0]['restores']==[{'advanced':True,'restored':True}]*2
    assert job['result']['sandbox']['network_mode']=='none'
    results.append({'feature':feature,'firmware_id':queued['firmware_id'],'job_id':queued['job_id'],'status':job['status'],'findings':len(report['findings'])})
    print(json.dumps(results[-1]),flush=True)
(out/'extended-results.json').write_text(json.dumps(results,indent=2)+'\n')
