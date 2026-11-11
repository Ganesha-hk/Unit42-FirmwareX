"""Real sandboxed angr verification. No target executes on host."""
import hashlib,json,os,shutil,uuid
from pathlib import Path
from firmwarex.config import settings
from firmwarex.analysis.controller import run
from firmwarex.database import factory
from firmwarex.models import Firmware
base=settings();records=[];fid=str(uuid.uuid4())
with factory()() as db:
 db.add(Firmware(id=fid,sha256='0'*64,size=0,provenance={'type':'controlled_fixture','license_id':'MIT'}));db.commit()
def case(name,budgets=None,architecture='x86_64'):
 job=str(uuid.uuid4());folder=base.storage/'jobs'/job/'input';root=folder/'rootfs';root.mkdir(parents=True)
 binary=root/name;shutil.copyfile(Path('/fixtures')/name,binary)
 request={'binary':name,'sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'architecture':architecture,'firmware_id':fid,'mode':'symbolic','budgets':budgets or {}}
 (folder/'request.json').write_text(json.dumps(request));None
 out=run(job,base.model_copy(update={'job_wall_seconds':90,'job_cpu_seconds':60,'job_memory_bytes':1024*1024*1024}),'/registry/analysis-controlled.json')
 import docker
 client=docker.from_env();assert not client.containers.list(all=True,filters={'label':'firmwarex.job_id='+job});client.close()
 records.append({'case':name,'job_id':job,**out});Path('/evidence/symbolic-smoke-results.json' if os.getenv('FWX_SMOKE') else '/evidence/symbolic-results.json').write_text(json.dumps(records,indent=2)+'\n')
 return out['result']
if os.getenv('FWX_SMOKE'):
 result=case(os.getenv('FWX_SMOKE_CASE','source0-sink0'));print(json.dumps({'status':result.get('status'),'findings':len(result.get('findings',[]))}));assert len(result['findings'])==1,result
else:
 for source in range(4):
  for sink in range(6):
   result=case(f'source{source}-sink{sink}');assert len(result.get('findings',[]))==1,(source,sink,result)
   finding=result['findings'][0];assert finding['source']==['fwx_cgi_stdin_0','fwx_network_0','fwx_cgi_query_0','fwx_environment_0'][source]
   assert finding['sink']==['strcpy','memcpy','sprintf','system','popen','sprintf'][sink]
   assert finding['cwe']==('CWE-78' if sink in (3,4) else 'CWE-134' if sink==5 else 'CWE-787')
   detail=result['evidence'][finding['evidence_ref']];assert detail['condition_satisfiable'] and detail['condition'] and finding['tainted_path']
   assert any(c.get('op')=='__eq__' and {'constant':65,'bits':8} in c.get('args',[]) for c in detail['condition'])

 result=case('chain');assert len(result['findings'])==1 and result['findings'][0]['sink']=='system',result
 for name in ['negative','unreachable','region3']:
  result=case(name);assert not result['findings'] and result['status']=='completed',(name,result)
 for name,cwe in [('region1','CWE-121'),('region2','CWE-122'),('fault','CWE-476')]:
  result=case(name);assert len(result['findings'])==1 and result['findings'][0]['cwe']==cwe,(name,result)
 for name,budgets,reason in [('loop',{'seconds':0.01},'time_budget'),('loop',{'depth':3},'depth_budget'),('branch',{'paths':1},'path_budget'),('branch',{'states':1,'merge':False},'state_budget'),('branch',{'memory_mb':1},'memory_budget'),('loop',{'steps':2},'step_budget')]:
  result=case(name,budgets);assert result['status']=='incomplete' and reason in result['reasons'],(name,result)
 result=case('branch');assert result['telemetry']['merged']>0,result
 for name,arch in [('mips','MIPS'),('mipsel','MIPSEL'),('arm','ARM32'),('aarch64','ARM64')]:
  result=case('cross-'+name,architecture=arch);assert len(result['findings'])==1 and result['findings'][0]['cwe']=='CWE-78',(name,result)
 print(json.dumps({'passed':len(records),'firmware_id':fid}))
