"""Build deterministic licensed controlled image; never execute targets."""
import hashlib,json,shutil,subprocess
from pathlib import Path
base=Path('/fixtures');root=base/'pipeline-root';(root/'bin').mkdir(parents=True,exist_ok=True);(root/'etc').mkdir(exist_ok=True)
for src,name in [(base/'analysis/source0-sink0','taint-demo'),(base/'emulation/x86_64','service-probe')]:shutil.copyfile(src,root/'bin'/name)
shutil.copyfile(base/'analysis/scanner.txt',root/'etc/controlled.conf')
(root/'etc'/'proprietary-sentinel-private').write_text('PROPRIETARY-CONTENT-SENTINEL\npassword=PipelineSecretSentinel123\n')
image=base/'controlled-pipeline.bin'
subprocess.run(['mksquashfs',str(root),str(image),'-noappend','-all-root','-no-progress','-processors','1','-mkfs-time','0','-all-time','0'],check=True,stdout=subprocess.DEVNULL)
manifest={'license':'MIT','images':{hashlib.sha256(image.read_bytes()).hexdigest():{'name':'controlled-pipeline','emulation':[{'binary':'bin/service-probe','architecture':'x86_64','sha256':hashlib.sha256((root/'bin/service-probe').read_bytes()).hexdigest()}],'symbolic':[{'binary':'bin/taint-demo','architecture':'x86_64','sha256':hashlib.sha256((root/'bin/taint-demo').read_bytes()).hexdigest()}]}}}
Path('/manifests/pipeline-controlled.json').write_text(json.dumps(manifest,indent=2)+'\n')
print('Built controlled pipeline image and exact-image execution registry.')
