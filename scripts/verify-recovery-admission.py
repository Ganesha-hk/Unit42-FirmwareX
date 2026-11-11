"""Real database/queue safety cases using isolated controlled test records."""
import json,uuid,time
from datetime import datetime,timedelta,timezone
import requests,docker
from sqlalchemy import select,delete
from firmwarex.config import settings
from firmwarex.database import factory
from firmwarex.models import Firmware,Job,AuditEvent
from firmwarex.tasks import redispatch
config=settings();client=docker.from_env();results={};ids=[]
with factory()() as db:
 firmware=Firmware(sha256='0'*64,size=0,provenance={'kind':'controlled_fixture','purpose':'admission-test'});db.add(firmware);db.flush();fid=firmware.id
 for i in range(config.max_pending_jobs):
  job=Job(firmware_id=fid,status='running');db.add(job);db.flush();ids.append(job.id)
 db.commit()
try:
 begin=time.monotonic()
 response=requests.post('http://api:8000/api/v1/firmware/upload',headers={'Authorization':'Bearer '+config.api_token},data={'provenance_kind':'controlled_fixture','license_id':'MIT'},files={'file':('controlled.bin',b'test')},timeout=5)
 assert response.status_code==429,response.text
 health=requests.get('http://api:8000/health',timeout=5);assert health.status_code==200
 results['admission']={'status':response.status_code,'health_status':health.status_code,'elapsed_seconds':round(time.monotonic()-begin,3),'inflight_limit':config.max_pending_jobs}
finally:
 with factory()() as db:db.execute(delete(Job).where(Job.id.in_(ids)));db.commit()
with factory()() as db:
 job=Job(firmware_id=fid,status='running',updated_at=datetime.now(timezone.utc)-timedelta(seconds=400));db.add(job);db.flush();jid=job.id;db.commit()
container=client.containers.run(config.static_image,entrypoint=['python','-c','import time; time.sleep(600)'],detach=True,network_mode='none',read_only=True,user='1000:1000',cap_drop=['ALL'],security_opt=['no-new-privileges:true'],mem_limit='64m',pids_limit=16,labels={'firmwarex.job_id':jid,'firmwarex.scope':'static'})
redispatch.run()
with factory()() as db:
 job=db.get(Job,jid);assert job.status=='failed' and job.error_code=='dispatcher_lost'
 spans=job.result['control_observability']['spans'];assert any(s['name']=='abandoned_job_recovery' for s in spans)
 event=db.scalar(select(AuditEvent).where(AuditEvent.job_id==jid,AuditEvent.event=='job_recovered'));assert event
assert not client.containers.list(all=True,filters={'label':'firmwarex.job_id='+jid})
results['recovery']={'job_id':jid,'status':'failed','reason':'dispatcher_lost','orphan_removed':True,'audit_recorded':True}
print(json.dumps(results,indent=2));client.close()
