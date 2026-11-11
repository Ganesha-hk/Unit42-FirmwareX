"""Trusted, audited launcher for registered analysis fixtures."""
import hashlib
import json
import os
from pathlib import Path
from uuid import UUID
from firmwarex.database import factory
from firmwarex.models import AuditEvent
from firmwarex.persistence import persist
from firmwarex.sandbox import launch
from firmwarex.analysis.budgets import validate_overrides

def salt_for_firmware(config,firmware_id):
    UUID(firmware_id)
    directory=config.storage/'private'/'fingerprints';directory.mkdir(parents=True,exist_ok=True,mode=0o700)
    path=directory/(firmware_id+'.salt')
    try:
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    except FileExistsError:
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        with os.fdopen(fd,'rb') as stream:salt=stream.read()
    else:
        salt=os.urandom(32)
        with os.fdopen(fd,'wb') as stream:stream.write(salt)
    if len(salt)!=32:raise ValueError('invalid private salt')
    return salt

def run(job_id,config,manifest_path):
    UUID(job_id);folder=config.storage/'jobs'/job_id/'input'
    request=json.loads((folder/'request.json').read_text())
    manifest=json.loads(Path(manifest_path).read_text())
    def audit(event,details):
        with factory()() as db:db.add(AuditEvent(job_id=job_id,event=event,details=details));db.commit()
    try:
        if set(request)-{'binary','sha256','architecture','firmware_id','mode','entry','budgets'}:raise ValueError('request fields')
        UUID(request['firmware_id'])
        name=request['binary']
        if not isinstance(name,str) or not name or Path(name).name!=name or name in {'.','..'}:raise ValueError('path')
        root=folder/'rootfs';binary=root/name
        if root.is_symlink() or binary.is_symlink() or not binary.is_file() or binary.stat().st_size>16*1024*1024 or list(root.iterdir())!=[binary]:raise ValueError('rootfs')
        digest=hashlib.sha256(binary.read_bytes()).hexdigest();registered=manifest.get('fixtures',{}).get(digest)
        if not registered or name!=registered['filename'] or request['architecture']!=registered['architecture'] or request['sha256']!=digest or request.get('entry','main')!='main' or request['mode']!=registered['mode']:raise ValueError('registry')
        budgets=request.get('budgets',{})
        validate_overrides(budgets)
    except (ValueError,KeyError,TypeError):
        audit('analysis_denied',{'reason':'controlled_fixture_gate'});raise PermissionError('valid registered fixture required') from None
    salt_path=folder/'fingerprint-salt'
    if salt_path.is_symlink():raise PermissionError('invalid salt path')
    salt_path.write_bytes(salt_for_firmware(config,request['firmware_id']))
    salt_path.chmod(0o400);os.chown(salt_path,config.sandbox_uid,config.sandbox_gid)
    audit('analysis_started',{'input_sha256':digest,'mode':request['mode'],'budgets':request.get('budgets',{})})
    try:result,telemetry=launch(job_id,config.model_copy(update={'static_image':'firmwarex-analysis:task4'}),scope='analysis')
    except Exception as error:
        audit('analysis_failed',{'error_type':type(error).__name__});raise
    if result.get('error_code'):
        result.update(status='incomplete',reasons=[result['error_code']],findings=[],evidence={})
    with factory()() as db:
        persist(db,job_id,result)
        db.add(AuditEvent(job_id=job_id,event='analysis_finished',details={'status':result.get('status','failed'),'sandbox':telemetry}))
        db.commit()
    return {'result':result,'sandbox':telemetry}
