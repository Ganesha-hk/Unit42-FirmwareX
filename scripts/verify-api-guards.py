import json,urllib.request,urllib.error,uuid
from pathlib import Path
root=Path(__file__).resolve().parents[1]
env=dict(l.split('=',1) for l in (root/'.env').read_text().splitlines())
base='http://127.0.0.1:8000';token=env['FWX_API_TOKEN'];rows=[]
for path,headers,expected in [('/api/v1/jobs/'+str(uuid.uuid4()),{},401),('/api/v1/jobs/'+str(uuid.uuid4()),{'Authorization':'Bearer incorrect'},401),('/api/v1/jobs/'+str(uuid.uuid4()),{'Authorization':'Bearer '+token},404),('/api/v1/jobs/invalid',{'Authorization':'Bearer '+token},422)]:
 try:
  urllib.request.urlopen(urllib.request.Request(base+path,headers=headers));status=200
 except urllib.error.HTTPError as e:status=e.code
 # HTTPBearer versions may use 403 for missing credentials.
 assert status==expected or (not headers and status==403),(status,expected)
 rows.append({'path':path,'expected':expected,'actual':status})
(root/'evidence/day1/api-guards.json').write_text(json.dumps(rows,indent=2)+'\n')
print('PASS: authentication, missing ID and invalid UUID guards')
