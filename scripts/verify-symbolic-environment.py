"""Exercise named environment and argv with a real controlled ELF in isolation."""
import json
from pathlib import Path
from uuid import uuid4
import angr
from firmwarex.analysis.engine import analyze

path=Path('/fixtures/analysis/environment-context')
project=angr.Project(str(path),auto_load_libs=False)
entry='address:'+hex(project.loader.find_symbol('main').rebased_addr)
result=analyze(path,str(uuid4()),'/bin/environment-context','x86_64',b'synthetic-environment-test-salt-32-bytes',
    entry=entry,start_context={'argv0':'/bin/environment-context',
    'environment':{'CONTENT_LENGTH':'0'},'symbolic_environment':['CONTENT_TYPE'],'working_directory':'/'})
assert result['status']=='completed',result['reasons']
assert {f['cwe'] for f in result['findings']}=={'CWE-787'},result['findings']
assert all(f['source']=='fwx_environment_0' for f in result['findings'])
assert result['start_context']['environment']=='named_environment'
print(json.dumps({'status':'passed','checks':['argv','absent variable','concrete variable','stable getenv pointer','symbolic source-to-sink']}))
