import hashlib
import json
from pathlib import Path
import pytest
from firmwarex.emulation.controller import authorize
from firmwarex.emulation.runner import command

@pytest.fixture
def registered(tmp_path):
 root=tmp_path/'root';root.mkdir();binary=root/'fixture';binary.write_bytes(b'controlled')
 digest=hashlib.sha256(binary.read_bytes()).hexdigest()
 manifest=tmp_path/'manifest.json';manifest.write_text(json.dumps({'fixtures':{digest:{'architecture':'ARM32','allowed_args':[[]]}}}))
 request={'binary':'fixture','architecture':'ARM32','sha256':digest}
 return root,manifest,request

def test_registered_fixture(registered):
 root,manifest,request=registered
 assert authorize(request,root,manifest)['sha256']==request['sha256']
 assert command(request,root)[0]=='qemu-arm'

@pytest.mark.parametrize('mutation',['hash','architecture','binary','args','kernel','extra_file','symlink'])
def test_gate_fails_closed(registered,mutation):
 root,manifest,request=registered
 if mutation=='hash':request['sha256']='0'*64
 elif mutation=='architecture':request['architecture']='MIPS'
 elif mutation=='binary':request['binary']='../../etc/passwd'
 elif mutation=='args':request['args']=['unregistered']
 elif mutation=='kernel':request['kernel']='fixture';request['kernel_sha256']=request['sha256']
 elif mutation=='extra_file':(root/'ld.so').write_bytes(b'untrusted')
 else:(root/'link').symlink_to('/etc/passwd')
 with pytest.raises(PermissionError):authorize(request,root,manifest)

def test_changed_binary_requires_signoff(registered):
 root,manifest,request=registered
 (root/'fixture').write_bytes(b'unregistered')
 request['sha256']=hashlib.sha256((root/'fixture').read_bytes()).hexdigest()
 with pytest.raises(PermissionError,match='not a registered controlled fixture'):authorize(request,root,manifest)

@pytest.mark.parametrize('args',[['x']*33,['x'*1025],42])
def test_bounded_arguments(registered,args):
 root,manifest,request=registered;request['args']=args
 with pytest.raises(ValueError,match='arguments'):command(request,root)

@pytest.mark.parametrize('field,value', [('unexpected','payload'),('timeout_seconds',0),('mode','shell'),('protocol','arbitrary')])
def test_request_schema_fails_closed(registered,field,value):
 root,manifest,request=registered;request[field]=value
 with pytest.raises(PermissionError):authorize(request,root,manifest)
