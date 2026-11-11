"""Bounded protocol mutation and diagnostic replay for registered fixtures only.

Every socket is fixed to job-private loopback; no user-supplied destination exists.
Guest execution belongs inside the production no-egress sandbox.
"""
import hashlib,json,os,re,socket,subprocess,time
from pathlib import Path
from firmwarex.emulation.runner import command
from firmwarex.fuzz.corpus import seeds,minimize
from firmwarex.findings import normalize
from firmwarex.output_policy import safe_path
from firmwarex.scanners.secrets import fingerprint


def trial(target,root,protocol,payload,seconds=3):
    if protocol not in {'http','upnp','mqtt'}:raise ValueError('unsupported protocol')
    if not payload or len(payload)>512:raise ValueError('input bound')
    cmd=command({**target,'args':[protocol]},root)
    guest=subprocess.Popen([cmd[0],'-g','12345',*cmd[1:]],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env={'PATH':os.environ['PATH'],'HOME':'/tmp'})
    debugger=None;deadline=time.monotonic()+seconds
    try:
        commands=['set pagination off','set print frame-arguments none','set confirm off','set debuginfod enabled off','set tcp connect-timeout 2','set tcp auto-retry on','file '+cmd[-2],'target remote 127.0.0.1:12345','continue','bt 12','printf "FWX_PC=%p\\n", $pc','printf "FWX_SP=%p\\n", $sp','quit']
        # QEMU opens the debugger socket immediately, before guest code starts.
        debugger=subprocess.Popen(['gdb-multiarch','-q','-nx','-batch','-iex','set auto-load off',*[arg for c in commands for arg in ('-ex',c)]],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env={'PATH':os.environ['PATH'],'HOME':'/tmp'})
        sent=False
        while time.monotonic()<deadline and debugger.poll() is None:
            try:
                if protocol=='upnp':
                    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:sock.sendto(payload,('127.0.0.1',18081))
                    # UDP has no connect handshake; resend until the guest exits.
                    sent=True;time.sleep(.025);continue
                with socket.create_connection(('127.0.0.1',18081),timeout=.1) as sock:sock.sendall(payload)
                sent=True;break
            except OSError:time.sleep(.025)
        output=debugger.communicate(timeout=max(.1,deadline-time.monotonic()))[0].decode(errors='replace')
        frames=re.findall(r'^#\d+\s+(?:0x[0-9a-f]+\s+in\s+)?([^\n]+)',output,re.M)
        addresses=re.findall(r'^#\d+\s+(0x[0-9a-f]+)',output,re.M)
        pc=re.search(r'FWX_PC=(0x[0-9a-f]+)',output);sp=re.search(r'FWX_SP=(0x[0-9a-f]+)',output)
        crash='Program received signal SIGSEGV' in output
        # Classification is only for this reviewed, hash-registered fixture's
        # intentional null write, not inferred for arbitrary crash addresses.
        known=crash and bool(frames) and 'controlled_null_write' in frames[0]
        if pc and (not addresses or addresses[0]!=pc[1]):addresses.insert(0,pc[1])
        return {'status':'crash' if crash else 'completed' if sent and 'exited normally' in output else 'incomplete','source_mapped_null_write':known,'frames':addresses,'pc':pc[1] if pc else None,'sp':sp[1] if sp else None,'stack_hash':hashlib.sha256('|'.join(addresses).encode()).hexdigest() if addresses else None}
    except subprocess.TimeoutExpired:return {'status':'incomplete','reason':'trial_timeout'}
    finally:
        for proc in [debugger,guest]:
            if proc:
                if proc.poll() is None:proc.kill()
                proc.wait()


def run(target,root,firmware_id,salt,registry,seed=42,seconds=90):
    if set(target)!={'binary','sha256','architecture'}:raise ValueError('target fields')
    registered=registry.get(target['sha256'])
    if not registered or registered['architecture']!=target['architecture'] or Path(target['binary']).name!=registered['binary']:raise PermissionError('unregistered fixture')
    if target['architecture']!='x86_64':raise PermissionError('fixture architecture')
    if type(seed) is not int or not 0<=seed<=2**32-1 or not 0<seconds<=90:raise ValueError('fuzz budget')
    root=Path(root);binary=(root/target['binary']).resolve()
    if not binary.is_relative_to(root.resolve()) or (root/target['binary']).is_symlink() or hashlib.sha256(binary.read_bytes()).hexdigest()!=target['sha256']:raise PermissionError('fixture hash')
    started=time.monotonic();runs=[];findings={};evidence={}
    for protocol in ['http','upnp','mqtt']:
        for index,payload in enumerate(seeds(protocol,seed)):
            if time.monotonic()-started>seconds:return {'status':'incomplete','reason':'fuzz_budget','runs':runs,'findings':list(findings.values()),'evidence':evidence}
            result=trial(target,root,protocol,payload)
            runs.append({'protocol':protocol,'seed_index':index,'status':result['status']})
            if result['status']!='crash' or not result['source_mapped_null_write'] or not result['stack_hash']:continue
            def reproduces(candidate):
                if time.monotonic()-started>seconds:return False
                replay=trial(target,root,protocol,candidate)
                return replay.get('stack_hash')==result['stack_hash'] and replay.get('source_mapped_null_write',False)
            reduced,attempts=minimize(payload,reproduces,max_attempts=12)
            replay=trial(target,root,protocol,reduced)
            stable=replay.get('stack_hash')==result['stack_hash'] and replay.get('source_mapped_null_write',False)
            if not stable:continue
            # Retain a deterministic deletion recipe, never raw input bytes.
            positions=[];offset=0
            for value in reduced:
                offset=payload.index(value,offset);positions.append(offset);offset+=1
            detail={'rule':'controlled_protocol_null_write','protocol':protocol,'seed':seed,'seed_index':index,'retained_indices':positions,'fingerprint':fingerprint(reduced,salt),'byte_length':len(reduced),'original_length':len(payload),'minimization_attempts':attempts,'replay_verified':True,'call_path':result['frames'],'redacted':True,'heuristic':False}
            # One stack per binary, independent of input/protocol, for dedup.
            ref='evidence:'+fingerprint((firmware_id+target['sha256']+result['stack_hash']).encode(),salt)
            finding=normalize(firmware_id=firmware_id,binary=safe_path('/'+target['binary'],salt),architecture=target['architecture'],category='memory_corruption',cwe='CWE-476',address=result['pc'],crash_state={'fault_address':'0x0','registers':{'pc':result['pc'],'sp':result['sp']},'overflow_offset':None,'stack_hash':result['stack_hash']},evidence_ref=ref,confidence='probable',risk_rating='medium')
            if ref in evidence:
                evidence[ref]['replays'].append(detail)
            else:evidence[ref]={'rule':'controlled_protocol_null_write','replays':[detail],'redacted':True}
            findings[finding['vulnerability_id']]=finding
    return {'status':'completed' if all(r['status']!='incomplete' for r in runs) else 'incomplete','runs':runs,'findings':list(findings.values()),'evidence':evidence,'wall_seconds':round(time.monotonic()-started,3)}


def main():
    import resource
    resource.setrlimit(resource.RLIMIT_CORE,(0,0));os.umask(0o077)
    try:
        request=json.loads(Path('/input/request.json').read_text());registry=json.loads(Path('/app/fuzz-controlled.json').read_text())
        result=run(request['target'],Path('/input/rootfs'),request['firmware_id'],Path('/input/fingerprint-salt').read_bytes(),registry)
    except Exception as error:result={'status':'failed','error_type':type(error).__name__}
    Path('/output/result.json').write_text(json.dumps({'schema_version':1,**result}))
if __name__=='__main__':main()
