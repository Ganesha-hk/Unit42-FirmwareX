import json,os,socket
from pathlib import Path
out={'uid':os.getuid(),'routes':Path('/proc/net/route').read_text(),'socket_present':Path('/var/run/docker.sock').exists()}
for path in ['/host-probe','/app/forbidden']:
 try:Path(path).write_text('x');out[path]='WRITABLE'
 except OSError:out[path]='denied'
# Network-none route checks avoid even attempting traffic to a third-party service.
out['interfaces']=sorted(p.name for p in Path('/sys/class/net').iterdir())
out['default_route']=any(line.split()[1]=='00000000' for line in out['routes'].splitlines()[1:])
out['effective_capabilities']=next(line.split(':')[1].strip() for line in Path('/proc/self/status').read_text().splitlines() if line.startswith('CapEff:'))
assert out['uid']!=0 and not out['socket_present'] and not out['default_route']
assert out['interfaces']==['lo'] and int(out['effective_capabilities'],16)==0
assert out['/host-probe']==out['/app/forbidden']=='denied'
print(json.dumps(out,indent=2))
