"""Sandbox entry point: no raw target text in persisted results or exceptions."""
import hashlib
import json
import os
from pathlib import Path
import resource
from firmwarex.analysis.engine import analyze
from firmwarex.scanners.secrets import scan

def main():
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    resource.setrlimit(resource.RLIMIT_FSIZE,(16*1024*1024,16*1024*1024))
    result={'schema_version':1,'status':'failed'}
    try:
        request=json.loads(Path('/input/request.json').read_text());root=Path('/input/rootfs')
        target=(root/request['binary']).resolve()
        if not target.is_relative_to(root) or not target.is_file():raise ValueError('invalid target')
        if hashlib.sha256(target.read_bytes()).hexdigest()!=request['sha256']:raise ValueError('hash mismatch')
        salt=Path('/input/fingerprint-salt').read_bytes()
        common={'firmware_id':request['firmware_id'],'architecture':request['architecture'],'salt':salt}
        if request['mode']=='symbolic':result=analyze(target,binary='/'+request['binary'],budgets=request.get('budgets'),entry=request.get('entry','main'),**common)
        elif request['mode']=='scan':
            if target.stat().st_size>16*1024*1024:result={'status':'incomplete','reason':'file_size_budget','findings':[],'evidence':{}}
            else:result=scan(target.read_bytes(),path='/'+request['binary'],**common)
        else:raise ValueError('invalid mode')
    except Exception as error:
        result={'status':'incomplete','reason':'analysis_error','error_type':type(error).__name__,'findings':[],'evidence':{}}
    result['schema_version']=1
    Path('/output/result.json').write_text(json.dumps(result))
if __name__=='__main__':main()
