"""Controlled workload tests using the production launch function/profile."""
import io,json,tarfile,uuid,os
from pathlib import Path
import docker
from firmwarex.config import settings
from firmwarex.sandbox import launch
client=docker.from_env();base=settings();results=[]
programs={
 'wall':'import time; time.sleep(60)',
 'cpu':'while True: pass',
 'memory':'import time\na=[]\nwhile True: a.append(bytearray(8*1024*1024)); time.sleep(.01)',
 'network':'''import socket,json,ctypes,os
from pathlib import Path
checks={}
s=socket.socket();s.settimeout(1)
try:s.connect(("172.17.0.1",45678));checks["host_connect"]="unexpected_success"
except OSError as e:checks["host_connect_errno"]=e.errno
finally:s.close()
for family, target in [(socket.AF_INET,("192.0.2.1",45678)), (socket.AF_INET6,("2001:db8::1",45678))]:
 sock=socket.socket(family,socket.SOCK_DGRAM)
 try:sock.sendto(b"controlled-containment-probe",target);raise AssertionError("unexpected route")
 except OSError as error:checks["udp_"+str(family)]=error.errno;assert error.errno in [101,113]
 finally:sock.close()
checks["interfaces"]=[p.name for p in Path("/sys/class/net").iterdir()]
checks["uid"]=os.getuid()
libc=ctypes.CDLL(None,use_errno=True)
checks["mount_return"]=libc.mount(b"none",b"/tmp",b"tmpfs",0,None)
checks["mount_errno"]=ctypes.get_errno()
checks["socket_present"]=Path("/var/run/docker.sock").exists()
assert checks["interfaces"]==["lo"] and checks["uid"]!=0
assert checks["mount_return"]==-1 and checks["mount_errno"]==1
assert checks.get("host_connect_errno") in [101,113] and not checks["socket_present"]
Path("/output/result.json").write_text(json.dumps({"schema_version":1,"checks":checks}))
'''}
for mode,program in programs.items():
 tag='firmwarex-controlled-'+mode+':test'
 archive=io.BytesIO()
 with tarfile.open(fileobj=archive,mode='w') as tar:
  for name,data in {'Dockerfile':'FROM firmwarex-static:day1\nCOPY probe.py /probe.py\nENTRYPOINT ["python", "/probe.py"]\n','probe.py':program}.items():
   b=data.encode();info=tarfile.TarInfo(name);info.size=len(b);tar.addfile(info,io.BytesIO(b))
 archive.seek(0);client.images.build(fileobj=archive,custom_context=True,tag=tag,rm=True)
 job=str(uuid.uuid4());folder=base.storage/'jobs'/job/'input';folder.mkdir(parents=True);(folder/'firmware.bin').write_bytes(b'controlled')
 config=base.model_copy(update={'static_image':tag,'job_wall_seconds':3 if mode=='wall' else 20,'job_cpu_seconds':1 if mode=='cpu' else 15,'job_memory_bytes':64*1024*1024})
 result,telemetry=launch(job,config,scope=os.environ.get("FWX_TEST_SCOPE","static"))
 expected={'wall':'wall_quota','cpu':'cpu_quota','memory':'memory_quota'}.get(mode)
 if expected:assert result.get('error_code')==expected,(mode,result,telemetry)
 else:assert 'checks' in result,(mode,result,telemetry)
 assert not client.containers.list(all=True,filters={'label':'firmwarex.job_id='+job})
 results.append({'mode':mode,'result':result,'telemetry':telemetry,'cleanup_verified':True})
print(json.dumps(results,indent=2))
client.close()
