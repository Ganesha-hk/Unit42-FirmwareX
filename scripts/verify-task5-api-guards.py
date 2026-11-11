import os,json,uuid,urllib.request,urllib.error
from pathlib import Path
root=Path(__file__).resolve().parents[1];env=dict(l.split('=',1) for l in (root/'.env').read_text().splitlines());base='http://127.0.0.1:8000';rows=[]
for route in ['report','vulnerabilities']:
 for identity,token,expected in [(str(uuid.uuid4()),None,401),(str(uuid.uuid4()),'incorrect',401),(str(uuid.uuid4()),env['FWX_API_TOKEN'],404),('invalid',env['FWX_API_TOKEN'],422)]:
  headers={} if token is None else {'Authorization':'Bearer '+token}
  try:
   with urllib.request.urlopen(urllib.request.Request(base+'/api/v1/firmware/'+identity+'/'+route,headers=headers)) as response:code=response.status
  except urllib.error.HTTPError as error:code=error.code
  assert code==expected or (token is None and code==403),(route,code,expected)
  rows.append({'route':route,'expected':expected,'actual':code})
(root/os.environ.get('FWX_EVIDENCE_DIR','evidence/task5')/'api-guards.json').write_text(json.dumps(rows,indent=2)+'\n');print('PASS: eight report/finding API guards')
