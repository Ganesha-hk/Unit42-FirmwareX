"""Add reproducible fixture images for the newly authorized optional stages."""
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

base, manifests = Path('/fixtures'), Path('/manifests')
registry = json.loads((manifests/'pipeline-controlled.json').read_text())
records=[]
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
for feature, original, architecture, binary in [
    ('fuzz', 'pipeline-root', 'x86_64', 'protocol-fuzz'),
    ('snapshots', 'pipeline-root-ARM32', 'ARM32', 'snapshot-arm.elf'),
]:
    root=base/('extended-root-'+feature)
    shutil.copytree(base/original,root,dirs_exist_ok=True)
    shutil.copyfile(base/binary,root/'bin'/binary)
    existing=next(value for value in registry['images'].values()
                  if value['name']==('controlled-pipeline' if feature=='fuzz' else 'controlled-pipeline-ARM32'))
    entry={**existing,'name':'controlled-extended-'+feature,feature:[{
        'binary':'bin/'+binary,'architecture':architecture,'sha256':sha(base/binary)}]}
    image=base/('controlled-extended-'+feature+'.bin')
    repeat=base/('controlled-extended-'+feature+'-repeat.bin')
    for path in [image,repeat]:
        subprocess.run(['mksquashfs',str(root),str(path),'-noappend','-all-root','-no-progress',
                        '-processors','1','-mkfs-time','0','-all-time','0'],check=True,stdout=subprocess.DEVNULL)
    assert sha(image)==sha(repeat)
    registry['images'][sha(image)]=entry
    records.append({'feature':feature,'image':image.name,'sha256':sha(image),'repeat_sha256':sha(repeat),'target':entry[feature][0]})
(manifests/'pipeline-controlled.json').write_text(json.dumps(registry,indent=2)+'\n')
Path('/evidence/extended-fixtures.json').write_text(json.dumps(records,indent=2)+'\n')
print(json.dumps({'deterministic_images':len(records)}))
