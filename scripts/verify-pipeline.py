"""HTTP integration, real queued pipeline, gate and redaction checks."""
import os,json,time,uuid,urllib.request,urllib.error
from pathlib import Path
root=Path(__file__).resolve().parents[1];env=dict(line.split('=',1) for line in (root/'.env').read_text().splitlines());headers={'Authorization':'Bearer '+env['FWX_API_TOKEN']};base='http://127.0.0.1:8000'
def get(path):
 with urllib.request.urlopen(urllib.request.Request(base+path,headers=headers),timeout=15) as response:return json.load(response)
def upload(path):
 boundary='fwx'+uuid.uuid4().hex;parts=[]
 for key,value in {'provenance_kind':'controlled_fixture','license_id':'MIT'}.items():parts.append((f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n{value}\r\n').encode())
 parts.append((f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="fixture.bin"\r\nContent-Type: application/octet-stream\r\n\r\n').encode()+path.read_bytes()+b'\r\n');parts.append(f'--{boundary}--\r\n'.encode())
 with urllib.request.urlopen(urllib.request.Request(base+'/api/v1/firmware/upload',data=b''.join(parts),headers={**headers,'Content-Type':'multipart/form-data; boundary='+boundary}),timeout=30) as response:return json.load(response)
out=root/os.environ.get('FWX_EVIDENCE_DIR','evidence/task5');out.mkdir(parents=True,exist_ok=True)
# Compose startup is asynchronous; wait for readiness with a finite deadline.
deadline=time.monotonic()+30
while True:
 try:
  get('/health');break
 except (OSError,urllib.error.URLError):
  if time.monotonic()>=deadline:raise
  time.sleep(0.5)
records=[]
for name,approved in [('controlled-pipeline.bin',True),('controlled-squashfs.bin',False)]:
 queued=upload(root/'work/fixtures'/name);deadline=time.monotonic()+210
 while True:
  job=get('/api/v1/jobs/'+queued['job_id'])
  if job['status'] not in {'queued','running'}:break
  assert time.monotonic()<deadline,job;time.sleep(1)
 report=get('/api/v1/firmware/'+queued['firmware_id']+'/report')
 (out/('controlled-report.json' if approved else 'gated-report.json')).write_text(json.dumps(report,indent=2)+'\n')
 assert job['status'] in {'complete','partial'},job
 stages=job['result']['stages']
 if approved:
  assert job['status']=='complete',stages
  assert any(f['category']=='memory_corruption' for f in report['findings'])
  assert any(f['category']=='hardcoded_secret' for f in report['findings'])
  assert report['jobs'][-1]['result']['graphs']
  assert any(f['cwe']=='CWE-676' and f['confidence']=='heuristic' for f in report['findings'])
  spans=job['result']['observability']['spans'];assert {s['name'] for s in spans}=={'pipeline','extract','static','emulation','symbolic','secrets_crypto','normalize'}
  control=job['result']['control_observability']['spans']
  assert {s['name'] for s in control}=={'upload','queue_wait','sandbox_execution','persistence'}
  assert len({s['trace_id'] for s in spans+control})==1
  assert next(s for s in spans if s['name']=='pipeline')['parent_span_id']==next(s for s in control if s['name']=='sandbox_execution')['span_id']
  encoded=json.dumps(report)
  for forbidden in ['PipelineSecretSentinel123','proprietary-sentinel-private','PROPRIETARY-CONTENT-SENTINEL','UnitTestPassword123','SYNTHETIC-NOT-A-REAL-KEY']:assert forbidden not in encoded
 else:
  if env.get('FWX_MENTOR_AUTHORIZED_EXECUTION','false').lower()=='true':
   assert stages['emulation']['authorization']=='sandboxed_execution' and stages['symbolic']['authorization']=='sandboxed_execution'
  else:
   assert stages['emulation']['status']=='blocked' and stages['symbolic']['status']=='blocked'
  assert job['status']=='partial'
 for suffix in ['','/filesystem','/binary-audit','/vulnerabilities']:get('/api/v1/firmware/'+queued['firmware_id']+suffix)
 records.append({'image':name,'firmware_id':queued['firmware_id'],'job_id':queued['job_id'],'status':job['status'],'findings':len(report['findings']),'approved_execution':approved})
(out/'pipeline-results.json').write_text(json.dumps(records,indent=2)+'\n');print(json.dumps({'passed':len(records),'results':records}))
