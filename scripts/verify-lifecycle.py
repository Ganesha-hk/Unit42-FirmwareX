"""Real persistence and injected infrastructure failures; no target execution."""
import json,uuid,time
from sqlalchemy import select
from firmwarex.database import factory
from firmwarex.models import Firmware,Job
from firmwarex.config import settings
from firmwarex.observability import Observer
import firmwarex.tasks as tasks
rows=[]
for case in ['launcher_exception','quota','invalid_result']:
 jid=str(uuid.uuid4());fid=str(uuid.uuid4());folder=settings().storage/'jobs'/jid/'input';folder.mkdir(parents=True)
 obs=Observer(jid);carrier=obs.interval('upload',time.time_ns()-1000,time.time_ns());initial={'trace_parent':carrier,'control_observability':obs.snapshot()};obs.close()
 with factory()() as db:
  db.add(Firmware(id=fid,sha256='0'*64,size=0,provenance={'kind':'controlled_fixture'}));db.flush();db.add(Job(id=jid,firmware_id=fid,result=initial));db.commit()
 original=tasks.launch
 def controlled(*args,**kwargs):
  if case=='launcher_exception':raise RuntimeError('PRIVATE-LAUNCH-SENTINEL')
  if case=='quota':return {'error_code':'wall_quota'},{'reason':'wall_quota'}
  return {'status':'complete','files':[],'binaries':[],'findings':[{'invalid':'PRIVATE-RESULT-SENTINEL'}],'evidence':{},'stages':{}},{}
 try:tasks.launch=controlled;tasks.analyze.run(jid)
 finally:tasks.launch=original
 with factory()() as db:
  job=db.get(Job,jid);assert job.status=='failed';trace=job.result['control_observability'];spans=trace['spans']
  assert {s['name'] for s in spans}=={'upload','queue_wait','sandbox_execution','persistence'}
  assert len({s['trace_id'] for s in spans})==1
  failed=next(s for s in spans if s['name']==('persistence' if case=='invalid_result' else 'sandbox_execution'))
  assert failed['status']=='ERROR' and failed['attributes']['outcome']=='failed'
  assert 'PRIVATE-' not in json.dumps(job.result)
  rows.append({'case':case,'job_id':jid,'error_code':job.error_code,'trace':trace})
print(json.dumps(rows,indent=2))
