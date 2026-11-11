"""Real QEMU integration; only locally compiled allowlisted controlled fixtures."""
import hashlib,json,shutil,uuid,os,sys
capture_only=os.getenv("FWX_CAPTURE_ONLY")=="1"
from pathlib import Path
import docker
from firmwarex.config import settings
from firmwarex.emulation.controller import emulate,authorize
from firmwarex.database import factory
from firmwarex.models import AuditEvent
from sqlalchemy import select
base=settings(); manifest=Path('/registry/emulation-controlled.json'); records=[];client=docker.from_env()
def run(name,arch,args=None,mode='user',kernel=False,**updates):
 job=str(uuid.uuid4());folder=base.storage/'jobs'/job/'input';root=folder/'rootfs';root.mkdir(parents=True)
 binary=root/name;shutil.copyfile(Path('/fixtures')/name,binary);binary.chmod(0o555)
 request={'binary':name,'architecture':arch,'sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'args':args or [],'mode':mode,'timeout_seconds':60}
 if kernel:
  shutil.copyfile('/fixtures/boot-arm.elf',root/'boot-arm.elf')
  request.update(kernel='boot-arm.elf',kernel_sha256=hashlib.sha256((root/'boot-arm.elf').read_bytes()).hexdigest(),timeout_seconds=2)
 if mode=='service':request['protocol']=args[0]
 (folder/'request.json').write_text(json.dumps(request))
 outcome=emulate(job,base.model_copy(update=updates),manifest)
 assert not client.containers.list(all=True,filters={'label':'firmwarex.job_id='+job})
 with factory()() as db:
  events=list(db.scalars(select(AuditEvent).where(AuditEvent.job_id==job).order_by(AuditEvent.id)))
  assert [e.event for e in events]==['emulation_started','emulation_finished']
 record={'job_id':job,'architecture':arch,'mode':mode,'args':args or [],**outcome,'cleanup_verified':True,'audit_verified':True};records.append(record)
 Path('/evidence/capture-integration.json' if capture_only else '/evidence/integration.json').write_text(json.dumps(records,indent=2)+'\n')
 return outcome
expected=hashlib.sha256(b'FirmwareX controlled fixture\n').hexdigest()
for name,arch in [('mips','MIPS'),('mipsel','MIPSEL'),('arm','ARM32'),('aarch64','ARM64'),('x86_64','x86_64')]:
 for repeat in range(0 if capture_only else 2):
  out=run(name,arch);assert out['result'].get('stdout_sha256')==expected,out
 for protocol in ['http','upnp','mqtt']:
  out=run(name,arch,[protocol],'service');assert out['result'].get('status')=='completed',out
 out=run(name,arch,['containment']);assert out['result'].get('returncode')==0,out
if capture_only:
 print(json.dumps({'passed':len(records),'capture_only':True}));client.close();sys.exit(0)
for arg,updates,reason in [('sleep',{'job_wall_seconds':2},'wall_quota'),('spin',{'job_cpu_seconds':1},'cpu_quota'),('memory',{'job_memory_bytes':128*1024*1024},'memory_quota')]:
 out=run('x86_64','x86_64',[arg],**updates);assert out['sandbox']['reason']==reason,out
out=run('arm','ARM32',mode='system');assert out['result']['reason']=='kernel_profile_required',out
out=run('arm','ARM32',mode='system',kernel=True);assert out['result'].get('console_sha256')==hashlib.sha256(b'FWX controlled boot\n').hexdigest(),out
out=run('nvram-arm','ARM32');assert out['result'].get('stdout_sha256')==hashlib.sha256(b'NVRAM stub contract passed\n').hexdigest(),out
print(json.dumps({'passed':len(records),'architectures':5,'repeat_runs':10,'service_probes':15,'guest_containment':5,'quota_breaches':3,'system_fallback':1,'controlled_boot':1,'nvram_stub':1}))
client.close()
