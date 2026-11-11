"""Real production upload/queue/pipeline/API validation of controlled images."""
import hashlib,json,time,uuid,urllib.request,urllib.error,os
from pathlib import Path
root=Path(__file__).resolve().parents[1];out=root/os.environ.get('FWX_EVIDENCE_DIR','evidence/cross-e2e');out.mkdir(parents=True,exist_ok=True);env=dict(l.split('=',1) for l in (root/'.env').read_text().splitlines() if '=' in l);headers={'Authorization':'Bearer '+env['FWX_API_TOKEN']};base='http://127.0.0.1:8000'
def get(path):
 with urllib.request.urlopen(urllib.request.Request(base+path,headers=headers),timeout=20) as response:return json.load(response)
def upload(image,name):
 boundary='fwx'+uuid.uuid4().hex;parts=[]
 for k,v in {'provenance_kind':'controlled_fixture','license_id':'MIT','display_name':name}.items():parts.append((f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n').encode())
 parts.extend([(f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="fixture.bin"\r\nContent-Type: application/octet-stream\r\n\r\n').encode()+image.read_bytes()+b'\r\n',f'--{boundary}--\r\n'.encode()])
 with urllib.request.urlopen(urllib.request.Request(base+'/api/v1/firmware/upload',data=b''.join(parts),headers={**headers,'Content-Type':'multipart/form-data; boundary='+boundary}),timeout=30) as response:return json.load(response)
build=json.loads((root/'evidence/cross-e2e/fixture-build.json').read_text());image=root/'work/fixtures/controlled-pipeline.bin'
cases=[{'architecture':'x86_64','endianness':'little','image':image.name,'sha256':hashlib.sha256(image.read_bytes()).hexdigest()}]+build
records=[]
for case in cases:
 arch=case['architecture'];image=root/'work/fixtures'/case['image'];assert hashlib.sha256(image.read_bytes()).hexdigest()==case['sha256']
 queued=upload(image,arch+' controlled E2E firmware');deadline=time.monotonic()+220
 while True:
  job=get('/api/v1/jobs/'+queued['job_id'])
  if job['status'] not in ['running','queued']:break
  if time.monotonic()>deadline:raise TimeoutError('bounded pipeline wait: '+arch)
  time.sleep(1)
 report=get('/api/v1/firmware/'+queued['firmware_id']+'/report');(out/(arch+'-report.json')).write_text(json.dumps(report,indent=2)+'\n')
 checks={};result=job.get('result') or {};stages=result.get('stages',{})
 checks['fixture_hash']=report['sha256']==case['sha256'];checks['pipeline_complete']=job['status']=='complete'
 checks['extraction']=result.get('extraction',{}).get('status')=='extracted';checks['inventory']=len(report['files'])>=6
 checks['architecture_endianness']=len(report['binaries'])==2 and all(b['architecture']==arch and b['endianness']==case['endianness'] for b in report['binaries'])
 checks['mitigations']=all({'nx','pie','relro','stack_canary','fortify','bits'}<=b.keys() for b in report['binaries']) and bool(report['binaries'])
 executions=stages.get('emulation',{}).get('executions',[])
 checks['qemu']=len(executions)==4 and all(x['status']=='completed' and x['architecture']==arch for x in executions) and executions[0].get('returncode')==0
 checks['service_probes']={x.get('probe',{}).get('protocol') for x in executions if 'probe' in x}=={'http','upnp','mqtt'}
 checks['symbolic']=stages.get('symbolic',{}).get('status')=='completed' and any(f['tainted_path'] and f['cwe']==('CWE-787' if arch=='x86_64' else 'CWE-78') for f in report['findings'])
 checks['scanner']=stages.get('secrets_crypto',{}).get('status')=='completed' and {'hardcoded_secret','weak_crypto'}<={f['category'] for f in report['findings']}
 checks['fingerprints']=any(e.get('fingerprint') and e.get('redacted') is True for e in report['evidence'].values())
 checks['redaction']=all(s not in json.dumps(report) for s in ['PipelineSecretSentinel123','PROPRIETARY-CONTENT-SENTINEL','proprietary-sentinel-private','UnitTestPassword123','SYNTHETIC-NOT-A-REAL-KEY'])
 checks['finding_architectures']=bool(report['findings']) and all(f['architecture']==arch for f in report['findings'])
 checks['cfg']=bool(result.get('graphs'))
 spans=result.get('observability',{}).get('spans',[])+result.get('control_observability',{}).get('spans',[])
 checks['tracing']=len(spans)==11 and len({s['trace_id'] for s in spans})==1
 sandbox=result.get('sandbox',{});profile=sandbox.get('profile',{})
 checks['sandbox']=sandbox.get('network_mode')=='none' and sandbox.get('read_only') is True and profile.get('CapDrop')==['ALL'] and not profile.get('Privileged',True) and profile.get('Memory')==805306368 and profile.get('NanoCpus')==1000000000 and profile.get('PidsLimit')==64
 api={suffix:get('/api/v1/firmware/'+queued['firmware_id']+suffix) for suffix in ['','/filesystem','/binary-audit','/vulnerabilities']}
 checks['api']=api['/filesystem']['files']==report['files'] and api['/binary-audit']['binaries']==report['binaries'] and api['/vulnerabilities']['findings']==report['findings']
 entry={**case,'firmware_id':queued['firmware_id'],'job_id':queued['job_id'],'status':job['status'],'result':'PASS' if all(checks.values()) else 'PARTIAL' if job['status']=='partial' else 'FAIL','checks':checks,'findings':len(report['findings']),'cwes':sorted({f['cwe'] for f in report['findings']}),'report':arch+'-report.json'};records.append(entry)
 (out/'pipeline-results.json').write_text(json.dumps(records,indent=2)+'\n');print(json.dumps({'architecture':arch,'result':entry['result'],'status':job['status'],'findings':entry['findings'],'failed_checks':[k for k,v in checks.items() if not v]}),flush=True)
assert all(r['result']=='PASS' for r in records),'See per-architecture recorded checks'
