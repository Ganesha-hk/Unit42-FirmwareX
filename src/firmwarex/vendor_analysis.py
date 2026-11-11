"""Bounded best-effort analysis for sandbox-authorized image uploads.

Runs only inside the existing network-none pipeline sandbox. No shell commands
or firmware output are exported. Help-mode startup is not a service test.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import socket
import time

from firmwarex.output_policy import safe_path

MAX_TARGETS = 3
OPENWRT_PROFILES = {
    '/bin/busybox': {'emulation': 'applet'},
    '/usr/sbin/uhttpd': {'emulation': 'http'},
    '/usr/libexec/cgi-io': {
        'symbolic_entry': 'address:0x402003',
        'start_context': {'argv0': '/usr/libexec/cgi-upload',
                          'environment': {'REQUEST_METHOD':'POST','CONTENT_LENGTH':'0'},
                          'symbolic_environment': ['CONTENT_TYPE'],
                          'symbolic_environment_prefixes': {'CONTENT_TYPE':'multipart/form-data; boundary='},
                          'working_directory': '/', 'stdin_eof': True},
        # This profile verifies a narrow valid multipart-header / empty-body
        # path. Taint arriving at strcpy is not itself an overflow finding.
        'input_scope': 'multipart_header_empty_body',
        'entry_evidence': {'function': 'main', 'address': '0x402003',
                           'input_calls': ['getenv'], 'sink_calls': ['strcpy'],
                           'binary_sha256': '897d4abfc18c8c679f5cb3657fb67080ecd75b00288f7e25a59f75c4b06ced0f'},
    },
}
OPENWRT_PROFILE_IMAGE_SHA256 = '8c88c338afad0535ab295a62e9555dc91f3bf5c8f4fc3bc67008adb2619f60e6'
OPENWRT_PROFILE_BINARY_SHA256 = {
    '/bin/busybox': '2f05c4e66e4edab3914b24e00a8c016db2b65f4165b56b7842b359c5c1f55e8c',
    '/usr/sbin/uhttpd': '02723a581496090ccc5d8b19da6bdd0e8fa8878e148dd99ae6be6c13fc5aa94b',
    '/usr/libexec/cgi-io': '897d4abfc18c8c679f5cb3657fb67080ecd75b00288f7e25a59f75c4b06ced0f',
}


def guest_resolve(root, name):
    """Resolve firmware symlinks inside the guest root, including absolute links."""
    root=root.resolve();pending=list(Path(name).parts);parts=[];hops=0
    while pending:
        part=pending.pop(0)
        if part in {'/','.'}:continue
        if part=='..':
            if not parts:raise ValueError('guest_path_escape')
            parts.pop();continue
        candidate=root.joinpath(*parts,part)
        if candidate.is_symlink():
            hops+=1
            if hops>40:raise ValueError('guest_link_cycle')
            target=Path(os.readlink(candidate))
            if target.is_absolute():parts=[]
            pending=list(target.parts)+pending
        else:parts.append(part)
    return root.joinpath(*parts)


def targets(root, binaries):
    candidates=[]
    for item in binaries:
        if any(part in {'lib','lib64'} for part in Path(item['path']).parts):continue
        if item['architecture'] not in {'MIPS','MIPSEL','ARM32','ARM64','x86_64'}:continue
        if item.get('elf_type')!='ET_EXEC' and not item.get('pie'):continue
        path=root/item['path'].lstrip('/')
        if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):continue
        if not path.is_file() or path.stat().st_size>8*1024*1024:continue
        candidates.append({**item,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
    candidates.sort(key=lambda b:(not any(x in Path(b['path']).name.lower() for x in ('http','cgi','busybox')), -len(b.get('banned_functions',[])), b['path']))
    return candidates[:MAX_TARGETS],len(candidates)


def openwrt_targets(root, binaries):
    """Select only the OpenWrt programs with a verified, meaningful profile."""
    by_path={item['path']: item for item in binaries}
    selected=[]
    for name in OPENWRT_PROFILES:
        item=by_path.get(name)
        if not item: continue
        path=root/name.lstrip('/')
        if path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(root.resolve()):
            digest=hashlib.sha256(path.read_bytes()).hexdigest()
            if digest==OPENWRT_PROFILE_BINARY_SHA256[name]:
                selected.append({**item,'sha256':digest})
    return selected,len([item for item in binaries if item['architecture'] in {'MIPS','MIPSEL','ARM32','ARM64','x86_64'}])


def stage_root(root, destination):
    """Copy regular guest files into bounded executable tmpfs; never host links."""
    root=root.resolve();destination.mkdir(mode=0o700)
    total=0;links=[]
    for parent,dirs,files in os.walk(root,followlinks=False):
        for name in dirs+files:
            src=Path(parent)/name;dst=destination/src.relative_to(root)
            if src.is_symlink():links.append((src,dst));continue
            if src.is_dir():dst.mkdir(parents=True,exist_ok=True);continue
            if not src.is_file():continue
            total+=src.stat().st_size
            if total>28*1024*1024:raise ValueError('execution_root_budget')
            dst.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(src,dst);dst.chmod(0o500)
    for src,dst in links:
        try:resolved=guest_resolve(root,src.relative_to(root))
        except ValueError:continue
        if not resolved.exists():continue
        inside=destination/resolved.relative_to(root)
        dst.parent.mkdir(parents=True,exist_ok=True)
        dst.symlink_to(os.path.relpath(inside,dst.parent))
    return destination


def bounded(command, seconds, output=None):
    """Kill the process group on success and timeout, including guest children."""
    with open(os.devnull,'wb') as null:
        proc=subprocess.Popen(command,stdout=null,stderr=null,start_new_session=True,
                              env={'PATH':os.environ['PATH'],'HOME':'/tmp','USER':'firmwarex','PYTHONPATH':'/app/src'})
        try:
            code=proc.wait(timeout=seconds)
            if output is not None:
                if output.is_symlink() or not output.is_file() or output.stat().st_size>4*1024*1024:
                    return {'status':'incomplete','reason':'missing_result'}
                return json.loads(output.read_text())
            return {'status':'completed' if code==0 else 'incomplete','returncode':code,
                    'reason':'startup_exit' if code else 'help_mode_only'}
        except subprocess.TimeoutExpired:
            return {'status':'incomplete','reason':'time_budget'}
        finally:
            try:os.killpg(proc.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            proc.wait()


def http_probe(command):
    """Probe a fixed loopback HTTP harness, with no firmware web scripts."""
    web=Path('/scratch/http-probe');web.mkdir(exist_ok=True)
    marker=b'firmwarex-http-verification\n';(web/'index.html').write_bytes(marker)
    # uhttpd requires world-readable web content even when its UID owns it.
    # Only this synthetic page is public inside the network-isolated job.
    web.chmod(0o755);(web/'index.html').chmod(0o644)
    proc=subprocess.Popen([*command,'-f','-p','127.0.0.1:18082','-h',str(web),'-c','/dev/null'],
                          stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True,
                          env={'PATH':os.environ['PATH'],'HOME':'/tmp','USER':'firmwarex'})
    deadline=time.monotonic()+5
    outcome={'status':'incomplete','startup':'pending','request':'not_sent','response':'not_checked','cleanup':'pending'}
    try:
        while time.monotonic()<deadline:
            if proc.poll() is not None:
                outcome.update(startup='exited',reason='startup_exit',returncode=proc.returncode)
                return outcome
            try:
                with socket.create_connection(('127.0.0.1',18082),timeout=.25) as sock:
                    outcome['startup']='listening'
                    sock.sendall(b'GET /index.html HTTP/1.0\r\nHost: localhost\r\n\r\n')
                    outcome['request']='sent'
                    response=b''
                    while len(response)<8192:
                        chunk=sock.recv(8192-len(response))
                        if not chunk:break
                        response+=chunk
                if response.startswith(b'HTTP/1.') and b' 200 ' in response.split(b'\r\n',1)[0] and response.endswith(marker):
                    outcome.update(status='completed',response='http_200_marker_verified',protocol='http',network='job_private_loopback',response_sha256=hashlib.sha256(response).hexdigest(),bytes=len(response),reason='http_harness_verified')
                    return outcome
                outcome['response']='unexpected'
            except OSError:pass
            time.sleep(.05)
        outcome['reason']='time_budget'
        return outcome
    finally:
        try:os.killpg(proc.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        proc.wait()
        outcome['cleanup']='process_reaped'


def complete_profile(report, profile):
    """Finish one declared objective while preserving broader engine limits."""
    objective=profile.get('objective')
    if not objective:return report
    matches=[finding for finding in report.get('findings',[]) if
             finding.get('cwe')==objective['cwe'] and finding.get('sink')==objective['sink'] and
             (finding.get('source') or '').startswith(objective['source_prefix'])]
    if not matches:return report
    result=dict(report)
    result['engine_status']=report.get('status')
    result['engine_reasons']=report.get('reasons',[])
    result['profile_status']='completed'
    result['reason']='selected_profile_objective_reached'
    result['coverage']='profile_objective_only'
    result['objective']={**objective,'matched_finding_ids':[finding['vulnerability_id'] for finding in matches]}
    return result


def run(root,binaries,firmware_id,salt,image_sha256=None):
    from firmwarex.emulation.runner import EMULATORS
    selected,total=targets(root,binaries)
    registry=Path('/app/openwrt-corpus.json')
    openwrt=registry.is_file() and image_sha256==OPENWRT_PROFILE_IMAGE_SHA256 and any(
        item['sha256']==image_sha256 for item in json.loads(registry.read_text())['images'])
    if openwrt: selected,total=openwrt_targets(root,binaries)
    profile_ready=not openwrt or len(selected)==len(OPENWRT_PROFILES)
    emulation=[];symbolic=[];findings=[];evidence={};graphs={}
    guest=None
    if selected:
        try:guest=stage_root(root,Path('/guest/vendor'))
        except (ValueError,OSError):pass
    for index,target in enumerate(selected):
        name=target['path'];safe=safe_path(name,salt)
        graph_request={'root':str(root),'binary':name.lstrip('/'),'sha256':target['sha256'],'mode':'cfg'}
        graph_input=Path('/scratch')/f'vendor-graph-request-{index}.json'
        graph_output=Path('/scratch')/f'vendor-graph-result-{index}.json'
        graph_input.write_text(json.dumps(graph_request))
        graphs[safe]=bounded([sys.executable,'-m','firmwarex.vendor_analysis',str(graph_input),str(graph_output)],10,graph_output)
        if guest is None:execution={'status':'incomplete','reason':'execution_root_budget'}
        else:
            binary=guest/name.lstrip('/')
            command=[EMULATORS[target['architecture']],'-L',str(guest),str(binary)]
            if openwrt and OPENWRT_PROFILES[name].get('emulation')=='http':execution=http_probe(command)
            elif openwrt and OPENWRT_PROFILES[name].get('emulation')=='applet':
                execution=bounded([*command,'true'],3)
                if execution.get('returncode')==0:execution['reason']='applet_verified'
            elif openwrt:execution={'status':'not_applicable','reason':'symbolic_profile_only'}
            else:
                execution=bounded([*command,'--help'],3)
                # A successful startup alone does not complete service analysis.
                execution['status']='incomplete'
        emulation.append({'binary':safe,'architecture':target['architecture'],**execution})
        profile=OPENWRT_PROFILES.get(name,{}) if openwrt else {}
        if openwrt and 'symbolic_entry' not in profile:
            symbolic.append({'binary':safe,'status':'not_applicable','reason':'no_symbolic_profile'})
            continue
        request={'root':str(root),'binary':name.lstrip('/'),'sha256':target['sha256'],
                 'architecture':target['architecture'],'firmware_id':firmware_id}
        if profile: request.update({'entry':profile['symbolic_entry'],'entry_evidence':profile['entry_evidence'],
                                    'start_context':profile['start_context']})
        request_path=Path('/scratch')/f'vendor-request-{index}.json'
        output=Path('/scratch')/f'vendor-result-{index}.json'
        request_path.write_text(json.dumps(request))
        report=bounded([sys.executable,'-m','firmwarex.vendor_analysis',str(request_path),str(output)],20,output)
        if profile:
            report=complete_profile(report,profile)
            report['input_scope']=profile.get('input_scope','profiled_input')
        findings+=report.get('findings',[]);evidence.update(report.get('evidence',{}))
        symbolic.append({'binary':safe,**{k:v for k,v in report.items() if k not in {'findings','evidence'}}})
    common={'authorization':'sandboxed_execution','candidate_count':total,'selected_count':len(selected),'target_limit':MAX_TARGETS,
            'coverage':'selected_profiles_only' if openwrt else 'bounded_sample'}
    emulation_checked=[row for row in emulation if row['status']!='not_applicable']
    symbolic_checked=[row for row in symbolic if row['status']!='not_applicable']
    emulation_complete=profile_ready and bool(emulation_checked) and all(row['status']=='completed' for row in emulation_checked)
    symbolic_complete=profile_ready and bool(symbolic_checked) and all(row['status']=='completed' for row in symbolic_checked)
    return {'emulation':{**common,'status':'completed' if emulation_complete else 'incomplete',
                         'reason':'selected_profiles_complete' if emulation_complete else ('profile_binary_mismatch' if not profile_ready else 'sampled_profiles' if openwrt else 'sampled_help_mode'),'executions':emulation},
            'symbolic':{**common,'status':'completed' if symbolic_complete else 'incomplete',
                        'reason':'selected_profiles_complete' if symbolic_complete else ('profile_binary_mismatch' if not profile_ready else 'bounded_sample'),'analyses':symbolic},
            'findings':findings,'evidence':evidence,'graphs':graphs}


def main():
    import resource
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    resource.setrlimit(resource.RLIMIT_FSIZE,(4*1024*1024,4*1024*1024))
    request=json.loads(Path(sys.argv[1]).read_text());root=Path(request['root']).resolve()
    target=(root/request['binary']).resolve()
    result={'status':'incomplete','reason':'analysis_error','findings':[],'evidence':{}}
    try:
        if set(request)-{'root','binary','sha256','architecture','firmware_id','entry','entry_evidence','start_context','mode'}:raise ValueError('request fields')
        if not target.is_relative_to(root) or hashlib.sha256(target.read_bytes()).hexdigest()!=request['sha256']:raise ValueError('target')
        if request.get('mode') == 'cfg':
            resource.setrlimit(resource.RLIMIT_AS,(768*1024*1024,768*1024*1024))
            from firmwarex.pipeline import graph_for
            result=graph_for(target,[])
        else:
            from firmwarex.analysis.engine import analyze
            salt=Path('/input/fingerprint-salt').read_bytes()
            result=analyze(target,request['firmware_id'],safe_path('/'+request['binary'],salt),request['architecture'],salt,
                           budgets={'seconds':20,'memory_mb':512,'steps':1000},entry=request.get('entry','program_entry'),
                           start_context=request.get('start_context'))
            if request.get('entry_evidence'): result['entry_evidence']=request['entry_evidence']
    except Exception as error:result['error_type']=type(error).__name__
    from firmwarex.output_policy import sanitize_output
    Path(sys.argv[2]).write_text(json.dumps(sanitize_output(result,Path('/input/fingerprint-salt').read_bytes())))

if __name__=='__main__':main()
