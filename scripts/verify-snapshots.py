"""Verify real memory restore twice under the production no-egress sandbox."""
import json
import shutil
import uuid
from pathlib import Path
import docker
from firmwarex.config import settings
from firmwarex.sandbox import launch

config = settings()
job = str(uuid.uuid4())
folder = config.storage/'jobs'/job/'input'
(folder/'rootfs').mkdir(parents=True)
registry = json.loads(Path('/registry/snapshot-controlled.json').read_text())
target = next(value for value in registry.values() if isinstance(value, dict) and 'binary' in value)
shutil.copyfile('/fixtures/snapshot-arm.elf', folder/'rootfs'/target['binary'])
(folder/'request.json').write_text(json.dumps({'target': target}))
result, telemetry = launch(job, config.model_copy(update={
    'static_image': 'firmwarex-snapshots:controlled', 'job_wall_seconds': 30}), scope='emulation')
Path('/evidence/snapshots.json').write_text(json.dumps({'result': result, 'sandbox': telemetry}, indent=2)+'\n')
assert result.get('status') == 'completed', result
assert result['restores'] == [{'advanced': True, 'restored': True}]*2
client = docker.from_env()
try:
    assert not client.containers.list(all=True, filters={'label': 'firmwarex.job_id='+job})
    assert not client.volumes.list(filters={'label': 'firmwarex.job_id='+job})
finally:
    client.close()
print(json.dumps({'passed': True, 'restores': 2, 'job_id': job}))
