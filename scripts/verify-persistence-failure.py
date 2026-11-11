"""Inject invalid worker output at persistence boundary; real DB rollback test."""
import json,uuid
from sqlalchemy import select
from firmwarex.database import factory
from firmwarex.models import Firmware,Job,FileEntry,AuditEvent
from firmwarex.config import settings
import firmwarex.tasks as tasks
jid=str(uuid.uuid4());fid=str(uuid.uuid4());folder=settings().storage/'jobs'/jid/'input';folder.mkdir(parents=True)
with factory()() as db:
 db.add(Firmware(id=fid,sha256='0'*64,size=0,provenance={'kind':'controlled_fixture','purpose':'persistence-rollback'}));db.flush();db.add(Job(id=jid,firmware_id=fid));db.commit()
original=tasks.launch
try:
 tasks.launch=lambda *a,**k:({'status':'complete','files':[{'path':'/test'}],'binaries':[],'findings':[{'invalid':'SENSITIVE-EXCEPTION-SENTINEL'}],'evidence':{},'stages':{}},{})
 tasks.analyze.run(jid)
finally:tasks.launch=original
with factory()() as db:
 job=db.get(Job,jid);assert job.status=='failed' and job.error_code=='result_persistence_failed'
 assert not list(db.scalars(select(FileEntry).where(FileEntry.firmware_id==fid)))
 assert 'SENSITIVE-EXCEPTION-SENTINEL' not in json.dumps(job.result)
 assert db.scalar(select(AuditEvent).where(AuditEvent.job_id==jid,AuditEvent.event=='pipeline_finished'))
print(json.dumps({'passed':True,'job_id':jid,'atomic_rollback':True,'failure_audited':True,'exception_redacted':True}))
