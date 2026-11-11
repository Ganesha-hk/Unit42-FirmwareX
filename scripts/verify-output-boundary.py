"""Adversarial legacy database fixture: reads are redacted before maintenance."""
import json,uuid,runpy
from pathlib import Path
import requests
from firmwarex.database import factory
from firmwarex.config import settings
from firmwarex.models import Firmware,Job,FileEntry,BinaryAudit
config=settings();fid=str(uuid.uuid4());jid=str(uuid.uuid4());sentinel='PRIVATE-LEGACY-SENTINEL'
value={'path':'/etc/'+sentinel,'type':'file','size':0,'hash':None,'unreviewed-field':sentinel}
with factory()() as db:
 db.add(Firmware(id=fid,sha256='0'*64,size=0,provenance={'kind':'controlled_fixture','display_name':'Output policy regression fixture'}));db.flush()
 db.add(Job(id=jid,firmware_id=fid,status='complete',stage='finished',result={'description':sentinel,'errors':[{'path':'/'+sentinel,'code':sentinel}]}))
 db.add(FileEntry(firmware_id=fid,entry=value));db.add(BinaryAudit(firmware_id=fid,audit={'path':'/'+sentinel,'architecture':sentinel}));db.commit()
folder=config.storage/'jobs'/jid/'output';folder.mkdir(parents=True);(folder/'result.json').write_text(json.dumps(value))
paths=[f'/firmware/{fid}/filesystem',f'/firmware/{fid}/binary-audit',f'/firmware/{fid}/report',f'/jobs/{jid}']
for path in paths:
 response=requests.get('http://api:8000/api/v1'+path,headers={'Authorization':'Bearer '+config.api_token},timeout=10);assert response.status_code==200
 assert sentinel not in response.text and 'redacted-' in response.text
runpy.run_path('/scripts/redact-historical-output.py',run_name='__main__')
with factory()() as db:
 assert sentinel not in json.dumps(db.get(Job,jid).result)
assert sentinel not in (folder/'result.json').read_text()
print(json.dumps({'passed':True,'legacy_fixture_job_id':jid,'api_surfaces':len(paths),'legacy_storage_sanitized':True,'raw_originals':'controller-only quarantine','mentor_gate':'PENDING HUMAN REVIEW'}))
