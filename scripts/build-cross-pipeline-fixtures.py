"""Package only previously registered project-owned artifacts; never execute them."""
import hashlib,json,shutil,subprocess
from pathlib import Path
base=Path('/fixtures');manifests=Path('/manifests');out=Path('/evidence')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
analysis=json.loads((manifests/'analysis-controlled.json').read_text())['fixtures'];emulation=json.loads((manifests/'emulation-controlled.json').read_text())['fixtures']
registry=json.loads((manifests/'pipeline-controlled.json').read_text());records=[]
for arch,short,endian in [('ARM32','arm','little'),('ARM64','aarch64','little'),('MIPS','mips','big'),('MIPSEL','mipsel','little')]:
 symbolic=base/'analysis'/('cross-'+short);service=base/'emulation'/short
 assert analysis[sha(symbolic)]=={'filename':'cross-'+short,'architecture':arch,'mode':'symbolic'}
 assert emulation[sha(service)]['architecture']==arch and emulation[sha(service)]['filename']==short
 root=base/('pipeline-root-'+arch);(root/'bin').mkdir(parents=True,exist_ok=True);(root/'etc').mkdir(exist_ok=True)
 shutil.copyfile(symbolic,root/'bin/taint-demo');shutil.copyfile(service,root/'bin/service-probe')
 shutil.copyfile(base/'analysis/scanner.txt',root/'etc/controlled.conf')
 (root/'etc/proprietary-sentinel-private').write_text('PROPRIETARY-CONTENT-SENTINEL\npassword=PipelineSecretSentinel123\n')
 image=base/('controlled-pipeline-'+arch+'.bin');repeat=base/('controlled-pipeline-'+arch+'-repeat.bin')
 for target in [image,repeat]:
  subprocess.run(['mksquashfs',str(root),str(target),'-noappend','-all-root','-no-progress','-processors','1','-mkfs-time','0','-all-time','0'],check=True,stdout=subprocess.DEVNULL)
 assert sha(image)==sha(repeat),'non-deterministic filesystem packaging'
 entry={'name':'controlled-pipeline-'+arch,'emulation':[{'binary':'bin/service-probe','architecture':arch,'sha256':sha(service)}],'symbolic':[{'binary':'bin/taint-demo','architecture':arch,'sha256':sha(symbolic)}]}
 registry['images'][sha(image)]=entry
 records.append({'architecture':arch,'endianness':endian,'image':image.name,'sha256':sha(image),'bytes':image.stat().st_size,'repeat_sha256':sha(repeat),'targets':entry,'source_files':{p.name:sha(p) for p in Path('/sources').glob('*') if p.name in ['symbolic.c','emulation.c']},'authorization':'existing controlled artifact hashes only','license':'MIT'})
temp=manifests/'pipeline-controlled.tmp';temp.write_text(json.dumps(registry,indent=2)+'\n');temp.replace(manifests/'pipeline-controlled.json');(out/'fixture-build.json').write_text(json.dumps(records,indent=2)+'\n');print(json.dumps({'deterministic_images':len(records),'registered_images':len(registry['images'])}))
