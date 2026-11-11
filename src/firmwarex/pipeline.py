"""One no-egress sandbox: extract → static → emulate → symbolic → scan → normalize."""
import hashlib,json,os,resource,time
from pathlib import Path
from firmwarex.extract import unpack,entropy
from firmwarex.inventory import inventory
from firmwarex.output_policy import safe_path,sanitize_inventory,sanitize_output
from firmwarex.observability import Observer
from firmwarex.scanners.secrets import scan,fingerprint
from firmwarex.findings import normalize

MAX_SCAN_BYTES=64*1024*1024

def attempt(operation):
    """Keep independent stages usable without exposing exception/guest text."""
    try:
        return operation()
    except Exception:
        return {'status': 'incomplete', 'reason': 'stage_error'}

def graph_for(path,tainted_paths):
    import angr
    project=angr.Project(str(path),auto_load_libs=False)
    cfg=project.analyses.CFGFast(normalize=True,function_starts=[project.loader.find_symbol('main').rebased_addr] if project.loader.find_symbol('main') else None)
    functions=[];tainted={a for p in tainted_paths for a in p}
    for function in sorted(cfg.kb.functions.values(),key=lambda f:f.addr):
        if not project.loader.main_object.contains_addr(function.addr):continue
        nodes=[{'id':hex(n.addr),'tainted':hex(n.addr) in tainted} for n in function.graph.nodes()]
        edges=[{'source':hex(a.addr),'target':hex(b.addr)} for a,b in function.graph.edges()]
        functions.append({'address':hex(function.addr),'name':function.name if function.name in {'main','_start'} else 'function_'+hex(function.addr),'nodes':nodes[:256],'edges':edges[:512],'incomplete':len(nodes)>256 or len(edges)>512})
        if len(functions)>=128:break
    return {'functions':functions,'method':'angr CFGFast','limits':{'functions':128,'nodes_per_function':256}}

def run(observer=None):
    ctx=json.loads(Path('/input/context.json').read_text());salt=Path('/input/fingerprint-salt').read_bytes();image=Path('/input/firmware.bin');digest=hashlib.sha256(image.read_bytes()).hexdigest()
    observer=observer or Observer(ctx['job_id'],ctx.get('trace_parent'));result={'schema_version':1,'files':[],'binaries':[],'errors':[],'findings':[],'evidence':{},'graphs':{},'stages':{},'analysis_scope':'integrated_gated','redacted':True}
    approved=json.loads(Path('/app/pipeline-controlled.json').read_text()).get('images',{}).get(digest)
    with observer.stage('pipeline'):
        with observer.stage('extract'):
            root,extraction=unpack(image,Path('/scratch'));result['entropy']=entropy(image);result['extraction']=extraction
            # Names in special-inode metadata must follow the same policy.
            for item in extraction.get('special_entries',[]):item['path']=safe_path(item['path'],salt);item.pop('device',None)
            result['stages']['extract']={'status':extraction['status']}
        with observer.stage('static'):
            files,binaries,errors=inventory(root);raw_binaries={b['path']:b for b in binaries}
            for special in extraction.get('special_entries', []):
                item = dict(special)
                partition = item.pop('partition')
                if len(extraction['filesystems']) > 1:
                    item['path'] = '/' + partition + item['path']
                files.append(item)
            files.sort(key=lambda item: item['path'])
            from firmwarex.static_findings import leads
            static_findings,static_evidence=leads(binaries,ctx["firmware_id"],salt)
            result["findings"]+=static_findings;result["evidence"].update(static_evidence)
            result['stages']['static']={'status':'completed' if not errors else 'incomplete','binary_count':len(binaries)}
        vendor=None
        if not approved and ctx.get('mentor_authorized_execution') is True:
            from firmwarex.vendor_analysis import run as run_vendor
            with observer.stage('vendor_analysis'):
                vendor=attempt(lambda: run_vendor(root,binaries,ctx['firmware_id'],salt,image_sha256=digest))
            result['findings']+=vendor.get('findings',[]);result['evidence'].update(vendor.get('evidence',{}))
        with observer.stage('emulation') as span:
            if approved:
                from firmwarex.emulation.runner import execute
                executions=[]
                for target in approved['emulation']:
                    executions.append(attempt(lambda: execute({**target,'timeout_seconds':5},root=root)))
                    for protocol in ['http','upnp','mqtt']:
                        executions.append(attempt(lambda: execute({**target,'mode':'service','args':[protocol],'protocol':protocol,'timeout_seconds':5},root=root)))
                result['stages']['emulation']={'status':'completed' if all(x['status']=='completed' for x in executions) else 'incomplete','executions':executions,'authorization':'exact_controlled_image_registry'}
                if result['stages']['emulation']['status'] != 'completed':observer.fail(span)
            elif vendor is not None:result['stages']['emulation']=vendor.get('emulation',{'status':'incomplete','reason':'stage_error'})
            else:result['stages']['emulation']={'status':'blocked','reason':'mentor_signoff_required'}
        with observer.stage('symbolic') as span:
            symbolic=[]
            if approved:
                from firmwarex.analysis.engine import analyze
                for target in approved['symbolic']:
                    def analyze_target():
                        path=(root/target['binary']).resolve()
                        if not path.is_relative_to(root.resolve()) or hashlib.sha256(path.read_bytes()).hexdigest()!=target['sha256']:raise ValueError('controlled target hash')
                        return analyze(path,ctx['firmware_id'],safe_path('/'+target['binary'],salt),target['architecture'],salt,budgets={'seconds':15,'memory_mb':512})
                    report=attempt(analyze_target)
                    result['findings']+=report.get('findings',[]);result['evidence'].update(report.get('evidence',{}))
                    if 'findings' in report:
                        graph=attempt(lambda: graph_for((root/target['binary']).resolve(),[f['tainted_path'] for f in report['findings']]))
                        result['graphs'][safe_path('/'+target['binary'],salt)]=graph
                        if graph.get('status') == 'incomplete':report['status']='incomplete';report.setdefault('reasons',[]).append('graph_error')
                    symbolic.append({k:v for k,v in report.items() if k not in {'findings','evidence'}})
                result['stages']['symbolic']={'status':'completed' if all(x['status']=='completed' for x in symbolic) else 'incomplete','analyses':symbolic}
                if result['stages']['symbolic']['status'] != 'completed':observer.fail(span)
            elif vendor is not None:result['stages']['symbolic']=vendor.get('symbolic',{'status':'incomplete','reason':'stage_error'})
            else:result['stages']['symbolic']={'status':'blocked','reason':'mentor_signoff_required'}
        if approved and approved.get('fuzz'):
            with observer.stage('fuzz') as span:
                from firmwarex.fuzz.runner import run as fuzz
                registry=json.loads(Path('/app/fuzz-controlled.json').read_text())
                campaigns=[]
                for target in approved['fuzz']:
                    report=attempt(lambda: fuzz(target,root,ctx['firmware_id'],salt,registry))
                    result['findings']+=report.get('findings',[])
                    result['evidence'].update(report.get('evidence',{}))
                    campaigns.append({k:v for k,v in report.items() if k not in {'findings','evidence'}})
                result['stages']['fuzz']={'status':'completed' if all(x['status']=='completed' for x in campaigns) else 'incomplete','analyses':campaigns}
                if result['stages']['fuzz']['status']!='completed':observer.fail(span)
        if approved and approved.get('snapshots'):
            with observer.stage('snapshots') as span:
                from firmwarex.emulation.snapshots import run as snapshot
                registry=json.loads(Path('/app/snapshot-controlled.json').read_text())
                restores=[attempt(lambda: snapshot(target,root,registry)) for target in approved['snapshots']]
                result['stages']['snapshots']={'status':'completed' if all(x['status']=='completed' for x in restores) else 'incomplete','analyses':restores}
                if result['stages']['snapshots']['status']!='completed':observer.fail(span)
        with observer.stage('secrets_crypto'):
            scanned=0;total=0;skipped=0;observations={'entropy_candidates':0,'certificates':0}
            arches={b['architecture'] for b in binaries if b['architecture'] in {'ARM32','ARM64','MIPS','MIPSEL','x86_64'}}
            default_arch=next(iter(arches)) if len(arches)==1 else None
            for item in files:
                if item['type']!='file':continue
                path=(root/item['path'].lstrip('/'))
                if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):skipped+=1;continue
                size=path.stat().st_size
                if size>16*1024*1024 or total+size>MAX_SCAN_BYTES:skipped+=1;continue
                total+=size
                arch=raw_binaries.get(item['path'],{}).get('architecture',default_arch)
                if arch not in {'ARM32','ARM64','MIPS','MIPSEL','x86_64'}:skipped+=1;continue
                scan_result=scan(path.read_bytes(),firmware_id=ctx['firmware_id'],path=safe_path(item['path'],salt),architecture=arch,salt=salt)
                for key,value in scan_result.get('observations',{}).items():observations[key]+=value
                result['findings']+=scan_result['findings'];result['evidence'].update(scan_result['evidence']);scanned+=1
            result['stages']['secrets_crypto']={'status':'incomplete' if skipped else 'completed','files_scanned':scanned,'files_skipped':skipped,'bytes_scanned':total,'observations':observations,'architecture_inheritance':'single known image architecture; ambiguous non-ELF files skipped'}
        with observer.stage('normalize'):
            result['findings']=list({f['vulnerability_id']:f for f in result['findings']}.values())
            result['files'],result['binaries'],result['errors']=sanitize_inventory(files,binaries,errors,salt)
            result['stages']['normalize']={'status':'completed','finding_count':len(result['findings'])}
    result['observability']=observer.snapshot()
    result['status']='complete' if extraction['status']=='extracted' and not errors and all(x['status']=='completed' or x['status']=='extracted' for x in result['stages'].values()) else 'partial'
    return result

def main():
    os.umask(0o077);resource.setrlimit(resource.RLIMIT_CORE,(0,0));resource.setrlimit(resource.RLIMIT_FSIZE,(512*1024*1024,512*1024*1024))
    observer=None
    try:
        ctx=json.loads(Path('/input/context.json').read_text());observer=Observer(ctx['job_id'],ctx.get('trace_parent'))
        result=run(observer)
    except Exception as error:
        result={'schema_version':1,'error_code':'pipeline_failed','error_type':type(error).__name__,'status':'incomplete'}
        if observer:result['observability']=observer.snapshot()
    finally:
        if observer:observer.close()
    encoded=json.dumps(sanitize_output(result,Path('/input/fingerprint-salt').read_bytes()))
    if len(encoded.encode())>32*1024*1024:encoded=json.dumps({'schema_version':1,'error_code':'report_size_limit','status':'incomplete'})
    temp=Path('/output/result.tmp');temp.write_text(encoded);temp.replace('/output/result.json')
if __name__=='__main__':main()
