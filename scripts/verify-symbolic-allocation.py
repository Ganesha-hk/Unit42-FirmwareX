"""Verify bounded malloc/strlen copy classification in the isolated image."""
import json
from pathlib import Path
from uuid import uuid4
import angr
from firmwarex.analysis.engine import analyze

def run(name):
    path=Path('/fixtures/analysis')/name
    project=angr.Project(str(path),auto_load_libs=False)
    entry='address:'+hex(project.loader.find_symbol('main').rebased_addr)
    return analyze(path,str(uuid4()),'/bin/'+name,'x86_64',b'allocation-model-regression-salt-32b',
        entry=entry,start_context={'argv0':'/bin/'+name,
        'environment':{},'symbolic_environment':['CONTENT_TYPE'],
        'working_directory':'/'})

safe=run('allocation-safe')
unsafe=run('allocation-unsafe')
truncated=run('allocation-truncated')
assert safe['status']=='completed',safe
assert not safe['findings'],safe['findings']
assert unsafe['status']=='completed',unsafe
assert [f['cwe'] for f in unsafe['findings']]==['CWE-122'],unsafe['findings']
assert truncated['status']=='incomplete',truncated
assert 'symbolic_allocation_truncated' in truncated['reasons'],truncated['reasons']
print(json.dumps({'status':'passed','checks':['safe strlen(input)+3 prefix copy',
    'undersized strlen(input)+2 copy','reported truncated symbolic allocation'], 'safe_telemetry':safe['telemetry'],
    'unsafe_cwe':unsafe['findings'][0]['cwe']}))
