"""Real QEMU/GDB fixture fuzzing inside production network-none sandbox."""
import json,shutil,uuid,os
from pathlib import Path
from firmwarex.config import settings
from firmwarex.sandbox import launch
from firmwarex.database import factory
from firmwarex.models import Firmware,Job
from firmwarex.persistence import persist
base=settings();jid=str(uuid.uuid4());fid=str(uuid.uuid4());home=base.storage/'jobs'/jid/'input';(home/'rootfs').mkdir(parents=True)
shutil.copyfile('/fixtures/protocol-fuzz',home/'rootfs/protocol-fuzz')
(home/'rootfs/protocol-fuzz').chmod(0o555)
registry=json.loads(Path('/registry/fuzz-controlled.json').read_text());target=next(iter(registry.values()))
(home/'request.json').write_text(json.dumps({'target':target,'firmware_id':fid}));salt=home/'fingerprint-salt';salt.write_bytes(os.urandom(32));salt.chmod(0o444)
with factory()() as db:
 db.add(Firmware(id=fid,sha256=target['sha256'],size=target and (home/'rootfs/protocol-fuzz').stat().st_size,provenance={'kind':'controlled_fixture','license_id':'MIT'}));db.flush();db.add(Job(id=jid,firmware_id=fid,status='running'));db.commit()
result,telemetry=launch(jid,base.model_copy(update={'static_image':'firmwarex-fuzz:controlled','job_wall_seconds':150}),scope='pipeline')
Path('/evidence/fuzz-result.json').write_text(json.dumps({'result':result,'sandbox':telemetry},indent=2)+'\n')
assert result.get('status')=='completed',result
assert len(result['runs'])==12 and {r['protocol'] for r in result['runs']}=={'http','upnp','mqtt'}
assert sum(r['status']=='crash' for r in result['runs'])>=3
assert result['findings'] and len(result['findings'])<sum(r['status']=='crash' for r in result['runs']), 'crash dedup not demonstrated'
for entry in result['evidence'].values():
 for replay in entry['replays']:assert replay['replay_verified'] and replay['byte_length']<=replay['original_length']
with factory()() as db:
 persist(db,jid,result)
 job=db.get(Job,jid);job.status='complete';job.stage='finished';job.result={'status':result['status'],'sandbox':telemetry}
 db.commit()
print(json.dumps({'passed':True,'trials':12,'findings':len(result['findings']),'job_id':jid}))
