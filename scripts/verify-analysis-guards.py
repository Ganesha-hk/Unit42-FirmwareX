"""Real DB tests for fail-closed analysis, safe persistence and reveal denial."""
import hashlib,json,shutil,uuid
from pathlib import Path
from sqlalchemy import select
from firmwarex.config import settings
from firmwarex.analysis.controller import run
from firmwarex.database import factory
from firmwarex.models import AuditEvent
from firmwarex.redaction import deny_reveal
base=settings();cases=[]
for mode in ['unknown_binary','traversal','symlink','extra_file','unknown_budget','text_budget','unknown_field','wrong_arch']:
 job=str(uuid.uuid4());root=base.storage/'jobs'/job/'input'/'rootfs';root.mkdir(parents=True)
 binary=root/'source0-sink0';shutil.copyfile('/fixtures/source0-sink0',binary)
 request={'binary':binary.name,'sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'architecture':'x86_64','firmware_id':str(uuid.uuid4()),'mode':'symbolic'}
 if mode=='unknown_binary':binary.write_bytes(b'unknown')
 elif mode=='traversal':request['binary']='../../secret'
 elif mode=='symlink':binary.unlink();binary.symlink_to('/etc/passwd')
 elif mode=='extra_file':(root/'extra').write_bytes(b'extra')
 elif mode=='unknown_budget':request['budgets']={'raw':'sensitive-test-value'}
 elif mode=='text_budget':request['budgets']={'seconds':'sensitive-test-value'}
 elif mode=='unknown_field':request['raw']='sensitive-test-value'
 elif mode=='wrong_arch':request['architecture']='ARM32'
 (root.parent/'request.json').write_text(json.dumps(request))
 try:run(job,base,'/registry/analysis-controlled.json')
 except PermissionError:pass
 else:raise AssertionError(mode)
 assert not (root.parent.parent/'output').exists()
 with factory()() as db:
  events=list(db.scalars(select(AuditEvent).where(AuditEvent.job_id==job)))
  assert len(events)==1 and events[0].event=='analysis_denied'
  assert 'sensitive-test-value' not in json.dumps(events[0].details)
 cases.append(mode)
job=str(uuid.uuid4())
with factory()() as db:
 try:deny_reveal(db,job,str(uuid.uuid4()))
 except PermissionError:pass
 else:raise AssertionError('raw reveal allowed')
with factory()() as db:assert db.scalar(select(AuditEvent).where(AuditEvent.job_id==job)).event=='raw_reveal_denied'
print(json.dumps({'passed':len(cases)+1,'prelaunch_denials':cases,'raw_reveal':'denied_and_audited'}))
