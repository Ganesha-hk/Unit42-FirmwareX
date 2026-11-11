"""Verify denial occurs before a sandbox starts, with durable audit."""
import hashlib,json,uuid
from pathlib import Path
import docker
from sqlalchemy import select
from firmwarex.config import settings
from firmwarex.emulation.controller import emulate
from firmwarex.database import factory
from firmwarex.models import AuditEvent
base=settings();job=str(uuid.uuid4());root=base.storage/'jobs'/job/'input'/'rootfs';root.mkdir(parents=True)
(root/'unregistered').write_bytes(b'not an executable')
request={'binary':'unregistered','architecture':'ARM32','sha256':hashlib.sha256(b'not an executable').hexdigest()}
(root.parent/'request.json').write_text(json.dumps(request))
try:emulate(job,base,Path('/registry/emulation-controlled.json'))
except PermissionError:pass
else:raise AssertionError('unregistered input accepted')
assert not (root.parent.parent/'output').exists()
with factory()() as db:
 events=list(db.scalars(select(AuditEvent).where(AuditEvent.job_id==job)))
 assert len(events)==1 and events[0].event=='emulation_denied'
client=docker.from_env()
assert not client.containers.list(all=True,filters={'label':'firmwarex.job_id='+job})
client.close()
print(json.dumps({'job_id':job,'unregistered_input':'refused_before_launch','audit':'emulation_denied','passed':True}))
