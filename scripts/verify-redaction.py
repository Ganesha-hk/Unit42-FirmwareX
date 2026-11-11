"""Prove scanner output, persisted rows and audit contain no synthetic secret text."""
import hashlib,json,shutil,uuid
from pathlib import Path
from sqlalchemy import select
from firmwarex.config import settings
from firmwarex.analysis.controller import run,salt_for_firmware
from firmwarex.scanners.secrets import fingerprint
from firmwarex.database import factory
from firmwarex.models import Firmware,Finding,FindingEvidence,AuditEvent
base=settings();fid=str(uuid.uuid4());jobs=[];results=[]
with factory()() as db:
 db.add(Firmware(id=fid,sha256='1'*64,size=0,provenance={'type':'controlled_fixture','license_id':'MIT'}));db.commit()
for repeat in range(2):
 job=str(uuid.uuid4());jobs.append(job);folder=base.storage/'jobs'/job/'input';root=folder/'rootfs';root.mkdir(parents=True)
 target=root/'scanner.txt';shutil.copyfile('/fixtures/scanner.txt',target)
 request={'binary':'scanner.txt','sha256':hashlib.sha256(target.read_bytes()).hexdigest(),'firmware_id':fid,'architecture':'ARM32','mode':'scan'}
 (folder/'request.json').write_text(json.dumps(request))
 result=run(job,base,'/registry/analysis-controlled.json');assert result['result']['status']=='completed',result
 results.append(result)
assert [f['vulnerability_id'] for f in results[0]['result']['findings']]==[f['vulnerability_id'] for f in results[1]['result']['findings']]
with factory()() as db:
 rows=[f.record for f in db.scalars(select(Finding).where(Finding.firmware_id==fid))]
 artifacts=[db.get(FindingEvidence,f['evidence_ref']).artifact for f in rows]
 audits=[e.details for e in db.scalars(select(AuditEvent).where(AuditEvent.job_id.in_(jobs)))]
assert len(rows)==len(results[0]['result']['findings'])>=6
encoded=json.dumps({'results':results,'rows':rows,'artifacts':artifacts,'audit':audits}).encode()
for needle in [b'UnitTestPassword123',b'Q7vM2xL9pR4nB8cK3sD6fH1j',b'SYNTHETIC-NOT-A-REAL-KEY',b'SYNTHETIC-CERTIFICATE',b'H5nZ2wC8qR4mA7vJ3xL9tB6k']:
 assert needle not in encoded
 for job in jobs:
  for path in (base.storage/'jobs'/job/'output').rglob('*'):
   if path.is_file():assert needle not in path.read_bytes()
assert any(a['fingerprint']==fingerprint(b'UnitTestPassword123',salt_for_firmware(base,fid)) for a in artifacts)
Path('/evidence/scanner-results.json').write_text(json.dumps({'firmware_id':fid,'results':results,'database_findings':rows,'database_evidence':artifacts,'audit':audits},indent=2)+'\n')
print(json.dumps({'passed':True,'repeat_runs':2,'persisted_findings':len(rows),'plaintext_matches':0,'stable_deduplication':True,'salt_private':True}))
