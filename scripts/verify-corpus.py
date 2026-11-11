import hashlib,json,time,urllib.request,uuid
from pathlib import Path
root=Path(__file__).resolve().parents[1]
env=dict(l.split('=',1) for l in (root/'.env').read_text().splitlines())
headers={'Authorization':'Bearer '+env['FWX_API_TOKEN']}
base='http://127.0.0.1:8000'
def get(p):
 return json.load(urllib.request.urlopen(urllib.request.Request(base+p,headers=headers),timeout=30))
manifest=json.loads((root/'fixtures/manifests/openwrt-24.10.4.json').read_text())
results=[]
for item in manifest['images']:
 boundary='fwx'+uuid.uuid4().hex
 data=b''
 for k,v in {'provenance_kind':'public_open_source','license_id':'GPL-2.0','source_url':item['url']}.items():
  data+=(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n').encode()
 data+=(f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="image.bin"\r\nContent-Type: application/octet-stream\r\n\r\n').encode()+(root/'work/corpus'/item['local_name']).read_bytes()+f'\r\n--{boundary}--\r\n'.encode()
 start=time.monotonic()
 req=urllib.request.Request(base+'/api/v1/firmware/upload',data=data,headers={**headers,'Content-Type':'multipart/form-data; boundary='+boundary})
 submitted=json.load(urllib.request.urlopen(req,timeout=60))
 while True:
  job=get('/api/v1/jobs/'+submitted['job_id'])
  if job['status'] not in ['queued','running']:break
  if time.monotonic()-start>240:raise RuntimeError('job timeout')
  time.sleep(1)
 fid=submitted['firmware_id'];files=get('/api/v1/firmware/'+fid+'/filesystem');audit=get('/api/v1/firmware/'+fid+'/binary-audit')
 success=job['status']=='static_complete' and bool(files['files']) and bool(audit['binaries'])
 row={'name':item['name'],'sha256':submitted['sha256'],'job':job,'inventory':files,'mitigation_matrix':audit,'success':success,'wall_seconds':round(time.monotonic()-start,3)}
 results.append(row)
 print(item['target'],job['status'],len(files['files']),len(audit['binaries']),flush=True)
 (root/'evidence/day1/corpus-results.json').write_text(json.dumps({'manifest':'fixtures/manifests/openwrt-24.10.4.json','denominator':6,'successes':sum(r['success'] for r in results),'results':results},indent=2)+'\n')
assert sum(r['success'] for r in results)/6>0.90
