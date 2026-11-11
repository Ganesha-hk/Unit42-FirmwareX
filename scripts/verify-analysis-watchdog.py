import hashlib,json,shutil,uuid
from pathlib import Path
import docker
from firmwarex.config import settings
from firmwarex.analysis.controller import run
base=settings();job=str(uuid.uuid4());root=base.storage/'jobs'/job/'input'/'rootfs';root.mkdir(parents=True)
shutil.copyfile('/fixtures/loop',root/'loop')
request={'binary':'loop','sha256':hashlib.sha256((root/'loop').read_bytes()).hexdigest(),'architecture':'x86_64','firmware_id':str(uuid.uuid4()),'mode':'symbolic'}
(root.parent/'request.json').write_text(json.dumps(request))
out=run(job,base.model_copy(update={'job_wall_seconds':1}),'/registry/analysis-controlled.json')
assert out['result']['status']=='incomplete' and out['sandbox']['reason']=='wall_quota',out
client=docker.from_env();assert not client.containers.list(all=True,filters={'label':'firmwarex.job_id='+job});client.close()
print(json.dumps({'passed':True,'job_id':job,'outcome':out,'cleanup_verified':True}))
