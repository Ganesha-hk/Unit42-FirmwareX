"""Verify errno storage and read(0) EOF behavior in the isolated analyzer."""
import json
from pathlib import Path
from uuid import uuid4
import angr
from firmwarex.analysis.engine import analyze

path=Path('/fixtures/analysis/runtime-models')
project=angr.Project(str(path),auto_load_libs=False)
result=analyze(path,str(uuid4()),'/bin/runtime-models','x86_64',b'runtime-model-regression-salt-32byte',
    entry='address:'+hex(project.loader.find_symbol('main').rebased_addr),
    start_context={'argv0':'/bin/runtime-models','environment':{},'working_directory':'/','stdin_eof':True})
assert result['status']=='completed',result
assert not result['findings'],result['findings']
assert result['start_context']['stdin_eof'] is True
assert result['telemetry']['terminal_returns']==[0],result['telemetry']
print(json.dumps({'status':'passed','checks':['writable errno storage','read standard-input EOF']}))
