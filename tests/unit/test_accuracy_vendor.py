import json
from pathlib import Path
from uuid import uuid4

from firmwarex.scanners.secrets import scan
from firmwarex.vendor_analysis import targets, stage_root, bounded

PARAMS=dict(firmware_id=str(uuid4()),path='/etc/config',architecture='MIPS',salt=b'accuracy-test-synthetic-salt-32-bytes')

def test_entropy_and_public_certificate_are_observations_not_vulnerabilities():
    result=scan(b'blob=H5nZ2wC8qR4mA7vJ3xL9tB6k\n-----BEGIN CERTIFICATE-----\nSYNTHETIC\n-----END CERTIFICATE-----',**PARAMS)
    assert result['findings']==[]
    assert result['observations']['certificates']==1
    assert result['observations']['entropy_candidates']>=1

def test_elf_string_boundaries_prevent_unrelated_crypto_context():
    assert not scan(b'authentication\x00md5\x00checksum',**PARAMS)['findings']
    assert len(scan(b'authentication_hash=md5\x00unrelated',**PARAMS)['findings'])==1

def test_assignment_stops_at_nul_and_ignores_code_placeholders():
    result=scan(b'password=SyntheticOnly123\x00private-neighbor\npassword=${variable}\npassword=%s\nsecret=null',**PARAMS)
    assert len(result['findings'])==1
    detail=next(iter(result['evidence'].values()))
    assert detail['byte_length']==len(b'SyntheticOnly123')
    assert 'SyntheticOnly123' not in json.dumps(result)

def test_target_selection_excludes_libraries_links_and_unsupported(tmp_path):
    (tmp_path/'program').write_bytes(b'test');(tmp_path/'link').symlink_to('/etc/passwd')
    base={'architecture':'MIPS','elf_type':'ET_EXEC','pie':False,'banned_functions':[]}
    rows=[{**base,'path':'/program'},{**base,'path':'/link'},{**base,'path':'/library','elf_type':'ET_DYN'}]
    selected,total=targets(tmp_path,rows)
    assert total==1 and selected[0]['path']=='/program'

def test_execution_root_rewrites_internal_absolute_links_and_omits_escape(tmp_path):
    root=tmp_path/'root';root.mkdir();(root/'lib').mkdir();(root/'lib/loader').write_bytes(b'fixture')
    (root/'inside').symlink_to('/lib/loader');(root/'outside').symlink_to('../../escape')
    dest=stage_root(root,tmp_path/'guest')
    assert (dest/'inside').resolve()==dest/'lib/loader'
    assert not (dest/'outside').exists()

def test_bounded_process_timeout_and_exit():
    import sys
    assert bounded([sys.executable,'-c','import time; time.sleep(30)'],.1)['reason']=='time_budget'
    assert bounded([sys.executable,'-c','raise SystemExit(4)'],1)['returncode']==4


def test_child_environment_has_nonroot_username():
    import sys
    result=bounded([sys.executable,'-c',"import os; assert os.environ['USER']=='firmwarex'"],2)
    assert result['returncode']==0


def test_nested_absolute_guest_loader_links_and_cycles(tmp_path):
    from firmwarex.vendor_analysis import guest_resolve
    root=tmp_path/'root';root.mkdir();(root/'lib').mkdir()
    (root/'lib/libc.so').write_bytes(b'guest libc')
    (root/'lib/loader').symlink_to('/lib/libc.so')
    (root/'loader').symlink_to('/lib/loader')
    (root/'cycle').symlink_to('/cycle')
    assert guest_resolve(root,'loader')==root/'lib/libc.so'
    dest=stage_root(root,tmp_path/'guest')
    assert (dest/'loader').read_bytes()==b'guest libc'
    assert not (dest/'cycle').exists()

def test_profile_completion_requires_declared_source_sink_and_cwe():
    from firmwarex.vendor_analysis import complete_profile
    profile={'objective':{'source_prefix':'fwx_environment_','sink':'strcpy','cwe':'CWE-120'}}
    finding={'vulnerability_id':'finding-1','source':'fwx_environment_0','sink':'strcpy','cwe':'CWE-120'}
    extra={**finding,'vulnerability_id':'finding-2','cwe':'CWE-476','source':None,'sink':None}
    report={'status':'incomplete','reasons':['depth_budget'],'findings':[finding,finding,extra],
            'evidence':{'evidence:1':{},'evidence:2':{}}}
    report['findings'][0]['evidence_ref']='evidence:1'
    completed=complete_profile(report,profile)
    assert completed['status']=='incomplete' and completed['profile_status']=='completed'
    assert completed['engine_status']=='incomplete' and completed['engine_reasons']==['depth_budget']
    assert completed['coverage']=='profile_objective_only'
    assert completed['findings']==report['findings']
    assert completed['evidence']==report['evidence']
    assert complete_profile({'status':'incomplete','findings':[{**finding,'sink':'memcpy'}]},profile)['status']=='incomplete'

def test_openwrt_cgi_profile_does_not_treat_taint_reaching_strcpy_as_an_overflow():
    from firmwarex.vendor_analysis import OPENWRT_PROFILES, complete_profile
    profile=OPENWRT_PROFILES['/usr/libexec/cgi-io']
    report={'status':'completed','reasons':[],'findings':[]}
    assert 'objective' not in profile
    assert complete_profile(report,profile)==report

def test_openwrt_profile_rejects_changed_binary(tmp_path):
    from firmwarex.vendor_analysis import openwrt_targets
    binary=tmp_path/'bin'/'busybox';binary.parent.mkdir();binary.write_bytes(b'changed firmware binary')
    selected,total=openwrt_targets(tmp_path,[{'path':'/bin/busybox','architecture':'x86_64'}])
    assert selected==[] and total==1

def test_openwrt_18065_profile_is_separate_and_checksum_bound(tmp_path):
    from firmwarex.vendor_analysis import OPENWRT_18065_PROFILE, openwrt_targets
    target=tmp_path/'usr'/'sbin'/'uhttpd';target.parent.mkdir(parents=True)
    target.write_bytes(b'changed')
    selected,total=openwrt_targets(tmp_path,[{'path':'/usr/sbin/uhttpd','architecture':'x86_64'}],OPENWRT_18065_PROFILE['binaries'],OPENWRT_18065_PROFILE['binaries'])
    assert total==1 and selected==[]

def test_runtime_profile_leaves_symbolic_incomplete(monkeypatch,tmp_path):
    import firmwarex.vendor_analysis as vendor
    root=tmp_path/'root';(root/'usr/sbin').mkdir(parents=True)
    binary=root/'usr/sbin/uhttpd'; binary.write_bytes(b'x')
    profile={'name':'openwrt_18_06_5_cve_2019_19945','binaries':{'/usr/sbin/uhttpd':__import__('hashlib').sha256(b'x').hexdigest()},'package_version':'2018-11-28-cdfc902a-3','expected_outcome':'crash_reproduced'}
    monkeypatch.setattr(vendor,'IMAGE_PROFILES',{'image':('openwrt_18_06_5',profile)})
    monkeypatch.setattr(vendor,'stage_root',lambda root,dest:root)
    monkeypatch.setattr(vendor,'cve_2019_19945_probe',lambda *args,**kwargs:{'status':'completed','outcome':'crash_not_reproduced','reason':'crash_not_reproduced','cleanup':'process_reaped'})
    monkeypatch.setattr(vendor,'bounded',lambda *args,**kwargs:{'status':'incomplete','reason':'graph_error'} if len(args)>2 else {'status':'incomplete','reason':'graph_error'})
    scratch=tmp_path/'scratch';scratch.mkdir()
    original=vendor.Path
    monkeypatch.setattr(vendor,'Path',lambda value: {'/app/openwrt-corpus.json':tmp_path/'missing','/scratch':scratch}.get(str(value),original(value)))
    result=vendor.run(root,[{'path':'/usr/sbin/uhttpd','architecture':'x86_64','elf_type':'ET_EXEC','pie':False}],str(uuid4()),b'synthetic-environment-test-salt-32-bytes',image_sha256='image')
    assert result['emulation']['executions'][0]['outcome']=='crash_not_reproduced'
    assert result['symbolic']['status']=='incomplete'


def test_generic_firmware_keeps_startup_probe(tmp_path,monkeypatch):
    import firmwarex.vendor_analysis as vendor
    root=tmp_path/'root';root.mkdir();(root/'program').write_bytes(b'controlled mock ELF')
    scratch=tmp_path/'scratch';scratch.mkdir()
    original_path=Path
    def mapped_path(value):
        return {'/scratch':scratch,'/guest/vendor':tmp_path/'guest',
                '/app/openwrt-corpus.json':tmp_path/'missing-registry'}.get(str(value),original_path(value))
    monkeypatch.setattr(vendor,'Path',mapped_path)
    calls=[]
    def bounded(command,seconds,output=None):
        calls.append(command)
        return {'status':'completed','returncode':0,'reason':'help_mode_only'} if output is None else {'status':'incomplete','findings':[],'evidence':{}}
    monkeypatch.setattr(vendor,'bounded',bounded)
    result=vendor.run(root,[{'path':'/program','architecture':'x86_64','elf_type':'ET_EXEC','pie':False}],str(uuid4()),b'synthetic-environment-test-salt-32-bytes')
    assert any(command[-1]=='--help' for command in calls)
    assert len(result['graphs'])==1
    assert next(iter(result['graphs'].values()))['status']=='incomplete'
    row=result['emulation']['executions'][0]
    assert row['status']=='incomplete' and row['reason']=='help_mode_only'
