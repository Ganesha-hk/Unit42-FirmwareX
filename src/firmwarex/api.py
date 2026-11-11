import time
from firmwarex.observability import Observer
import hashlib
import hmac
import os
import shutil
import uuid
from datetime import datetime
from typing import Annotated
from urllib.parse import urlparse
from fastapi import FastAPI, Depends, File, Form, HTTPException, Security, UploadFile
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select, func, text
from sqlalchemy.orm import Session
from firmwarex.config import settings
from firmwarex.database import session
from firmwarex.models import Firmware, Job, FileEntry, BinaryAudit, AuditEvent
from firmwarex.auth import authorize, router as auth_router
from fastapi.exceptions import RequestValidationError
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.responses import JSONResponse

api = FastAPI(title="FirmwareX", version="0.1.0", description="Contained firmware analysis with explicit execution approval gates.")
api.include_router(auth_router)

@api.middleware('http')
async def private_responses(request, call_next):
    response = await call_next(request)
    if request.url.path.startswith('/api/') or request.url.path == '/':
        response.headers['Cache-Control'] = 'no-store'
    return response

@api.exception_handler(RequestValidationError)
async def validation_error(request, exc):
    if request.url.path.startswith('/api/v1/auth/'):
        # Never echo submitted passwords or registration codes in validation errors.
        return JSONResponse(status_code=422, content={'detail': 'Use a valid employee ID and a password of 12–128 characters. Registration also requires the company code.'}, headers={'Cache-Control': 'no-store'})
    return await request_validation_exception_handler(request, exc)

guard = [Depends(authorize)]

def normalize_execution_labels(value):
    """Present neutral execution terms, including historical report records."""
    if isinstance(value, dict):
        return {key: normalize_execution_labels(child) for key, child in value.items()}
    if isinstance(value, list):
        return [normalize_execution_labels(child) for child in value]
    if isinstance(value, str):
        return {'mentor_authorized': 'sandboxed_execution',
                'mentor_signoff_required': 'execution_disabled',
                'blocked_pending_mentor_approval': 'execution_disabled'}.get(value, value)
    return value

def public_output(value,firmware_id):
    from firmwarex.output_policy import sanitize_output
    salt=hmac.digest(settings().api_token.encode(),('legacy-output:'+str(firmware_id)).encode(),'sha256')
    return normalize_execution_labels(sanitize_output(value,salt))


@api.get("/health")
def health():
    return {"status": "ok", "scope": "integrated_gated"}

def firmware_or_404(db, firmware_id):
    item = db.get(Firmware, str(firmware_id))
    if not item:
        raise HTTPException(404, "Firmware not found")
    return item

@api.post("/api/v1/firmware/upload", status_code=202, dependencies=guard)
def upload(
    file: Annotated[UploadFile, File()],
    provenance_kind: Annotated[str, Form(pattern="^(controlled_fixture|public_open_source)$")],
    license_id: Annotated[str, Form(min_length=1, max_length=64, pattern="^[A-Za-z0-9.+-]+$")],
    source_url: Annotated[str, Form(max_length=2048)] = "",
    display_name: Annotated[str, Form(max_length=80)] = "",
    db: Session = Depends(session),
):
    config = settings()
    if not (file.filename or "").lower().endswith((".bin", ".img")):
        raise HTTPException(422, "Expected .bin or .img")
    if provenance_kind == "public_open_source":
        parsed = urlparse(source_url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise HTTPException(422, "Public source HTTPS URL without credentials/query required")
    elif source_url:
        raise HTTPException(422, "Controlled fixtures do not use a remote URL")
    # Serialize admission checks across API processes.
    db.execute(text("SELECT pg_advisory_xact_lock(42001)"))
    pending = db.scalar(select(func.count()).select_from(Job).where(Job.status.in_(["queued", "running"])))
    if pending >= config.max_pending_jobs:
        raise HTTPException(429, "Analysis queue is full")
    firmware_id, job_id = str(uuid.uuid4()), str(uuid.uuid4())
    upload_started_ns=time.time_ns()
    observer=Observer(job_id)
    home = config.storage / "jobs" / job_id
    input_dir = home / "input"
    input_dir.mkdir(parents=True, mode=0o755)
    image = input_dir / "firmware.bin"
    size, digest = 0, hashlib.sha256()
    committed = False
    try:
        with image.open("xb") as output:
            # This synchronous endpoint runs in FastAPI's thread pool. Never
            # wait for a synchronous database lock on the ASGI event loop.
            while block := file.file.read(1024 * 1024):
                size += len(block)
                if size > config.max_upload_bytes:
                    raise HTTPException(413, "Image exceeds upload limit")
                digest.update(block)
                output.write(block)
        if size == 0:
            raise HTTPException(422, "Empty firmware")
        image.chmod(0o444)
        provenance = {"display_name": display_name.strip(), "kind": provenance_kind, "license_id": license_id, "source_fingerprint": hashlib.sha256(source_url.encode()).hexdigest() if source_url else None}
        db.add(Firmware(id=firmware_id, sha256=digest.hexdigest(), size=size, provenance=provenance))
        db.flush()
        parent=observer.interval("upload",upload_started_ns,time.time_ns())
        db.add(Job(id=job_id, firmware_id=firmware_id,result={"control_observability":observer.snapshot(),"trace_parent":parent}))
        db.add(AuditEvent(job_id=job_id, event="uploaded",
            details={"firmware_id": firmware_id, "sha256": digest.hexdigest(),
                     "size": size, "provenance": provenance, "scope": "integrated_gated"}))
        db.commit()
        committed = True
        # Durable queued rows are redispatched by beat if the broker is unavailable.
        from firmwarex.tasks import analyze
        try:
            analyze.apply_async(args=[job_id], retry=False)
        except Exception:
            pass
        return {"firmware_id": firmware_id, "job_id": job_id, "sha256": digest.hexdigest(),
                "status": "queued", "analysis_scope": "integrated_gated"}
    finally:
        observer.close()
        file.file.close()
        if not committed:
            db.rollback()
            shutil.rmtree(home, ignore_errors=True)

@api.post('/api/v1/firmware/{firmware_id}/reanalyze', status_code=202, dependencies=guard)
def reanalyze(firmware_id: uuid.UUID, db: Session = Depends(session)):
    """Create an immutable new assessment; retain the earlier report for comparison."""
    item=firmware_or_404(db,firmware_id)
    previous=db.scalars(select(Job).where(Job.firmware_id==item.id).order_by(Job.created_at.desc())).first()
    if not previous:raise HTTPException(404,'Original input unavailable')
    source=settings().storage/'jobs'/previous.id/'input/firmware.bin'
    if not source.is_file():raise HTTPException(404,'Original input unavailable')
    config=settings()
    db.execute(text("SELECT pg_advisory_xact_lock(42001)"))
    pending=db.scalar(select(func.count()).select_from(Job).where(Job.status.in_(['queued','running'])))
    if pending>=config.max_pending_jobs:raise HTTPException(429,'Analysis queue is full')
    fid,jid=str(uuid.uuid4()),str(uuid.uuid4())
    home=config.storage/'jobs'/jid;folder=home/'input';folder.mkdir(parents=True,mode=0o755)
    committed=False
    try:
        image=folder/'firmware.bin';shutil.copyfile(source,image);image.chmod(0o444)
        if hashlib.sha256(image.read_bytes()).hexdigest()!=item.sha256:raise HTTPException(409,'Original input hash mismatch')
        provenance={**item.provenance,'display_name':friendly_name(item)[:65]+' (reviewed)'}
        db.add(Firmware(id=fid,sha256=item.sha256,size=item.size,provenance=provenance));db.flush()
        db.add(Job(id=jid,firmware_id=fid))
        db.add(AuditEvent(job_id=jid,event='reanalysis_requested',details={'source_firmware_id':item.id,'sha256':item.sha256,'provenance':provenance}))
        db.commit();committed=True
    finally:
        if not committed:
            db.rollback();shutil.rmtree(home,ignore_errors=True)
    from firmwarex.tasks import analyze
    try:analyze.apply_async(args=[jid],retry=False)
    except Exception:pass
    return {'firmware_id':fid,'job_id':jid,'sha256':item.sha256,'status':'queued'}

@api.get("/api/v1/firmware/{firmware_id}", dependencies=guard)
def summary(firmware_id: uuid.UUID, db: Session = Depends(session)):
    item = firmware_or_404(db, firmware_id)
    jobs = db.scalars(select(Job).where(Job.firmware_id == item.id).order_by(Job.created_at)).all()
    return {"firmware_id": item.id, "sha256": item.sha256, "size": item.size,
            "jobs": [{"job_id": j.id, "status": j.status, "stage": j.stage} for j in jobs],
            "analysis_scope": "integrated_gated"}

@api.get("/api/v1/firmware/{firmware_id}/filesystem", dependencies=guard)
def filesystem(firmware_id: uuid.UUID, db: Session = Depends(session)):
    item = firmware_or_404(db, firmware_id)
    return {"firmware_id": item.id, "files": public_output(list(db.scalars(select(FileEntry.entry).where(FileEntry.firmware_id == item.id))),item.id)}

@api.get("/api/v1/firmware/{firmware_id}/binary-audit", dependencies=guard)
def binary_audit(firmware_id: uuid.UUID, db: Session = Depends(session)):
    item = firmware_or_404(db, firmware_id)
    return {"firmware_id": item.id, "binaries": public_output(list(db.scalars(select(BinaryAudit.audit).where(BinaryAudit.firmware_id == item.id))),item.id)}

@api.get("/api/v1/jobs/{job_id}", dependencies=guard)
def job_status(job_id: uuid.UUID, db: Session = Depends(session)):
    item = db.get(Job, str(job_id))
    if not item:
        raise HTTPException(404, "Job not found")
    return {"job_id": item.id, "firmware_id": item.firmware_id, "status": item.status,
            "stage": item.stage, "error_code": item.error_code, "result": public_output(item.result,item.firmware_id),
            "created_at": item.created_at, "updated_at": item.updated_at}

class UploadLimit:
    """Reject oversized bodies before multipart parsing/spooling."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("method") != "POST":
            return await self.app(scope, receive, send)
        from starlette.responses import JSONResponse
        limit = 8192 if scope.get('path', '').startswith('/api/v1/auth/') else settings().max_upload_bytes + 1024 * 1024
        size = 0
        async def bounded_receive():
            nonlocal size
            message = await receive()
            size += len(message.get("body", b""))
            if size > limit:
                raise HTTPException(413, "Request body exceeds upload limit")
            return message
        headers = dict(scope.get("headers", []))
        try:
            length = int(headers.get(b"content-length", b"0"))
        except ValueError:
            return await JSONResponse({"detail": "Invalid content length"}, 400)(scope, receive, send)
        if length > limit:
            return await JSONResponse({"detail": "Request body exceeds upload limit"}, 413)(scope, receive, send)
        await self.app(scope, bounded_receive, send)

app = UploadLimit(api)

# Read-only views expose normalized records, never raw firmware or rootfs bytes.
from pathlib import Path
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from firmwarex.models import Finding,FindingEvidence

@api.get('/api/v1/firmware',dependencies=guard)
def list_firmware(db:Session=Depends(session)):
    items=db.scalars(select(Firmware).order_by(Firmware.created_at.desc()).limit(100)).all()
    return {'firmware':[{'firmware_id':f.id,'sha256':f.sha256,'size':f.size,'created_at':f.created_at,'display_name':friendly_name(f)} for f in items]}

@api.get('/api/v1/firmware/{firmware_id}/vulnerabilities',dependencies=guard)
def vulnerabilities(firmware_id:uuid.UUID,db:Session=Depends(session)):
    item=firmware_or_404(db,firmware_id)
    return {'firmware_id':item.id,'schema_version':'1.0.0','findings':public_output(list(db.scalars(select(Finding.record).where(Finding.firmware_id==item.id))),item.id)}

@api.get('/api/v1/firmware/{firmware_id}/report',dependencies=guard)
def report(firmware_id:uuid.UUID,db:Session=Depends(session)):
    item=firmware_or_404(db,firmware_id)
    jobs=db.scalars(select(Job).where(Job.firmware_id==item.id).order_by(Job.created_at)).all()
    findings=public_output(list(db.scalars(select(Finding.record).where(Finding.firmware_id==item.id))),item.id)
    refs={f['evidence_ref'] for f in findings}
    evidence={ref:row.artifact for ref in refs if (row:=db.get(FindingEvidence,ref)) is not None}
    return {'schema_version':'1.0.0','firmware_id':item.id,'display_name':friendly_name(item),'sha256':item.sha256,'size':item.size,'redacted':True,'files':public_output(list(db.scalars(select(FileEntry.entry).where(FileEntry.firmware_id==item.id))),item.id),'binaries':public_output(list(db.scalars(select(BinaryAudit.audit).where(BinaryAudit.firmware_id==item.id))),item.id),'findings':findings,'evidence':public_output(evidence,item.id),'jobs':[{'job_id':j.id,'status':j.status,'stage':j.stage,'result':public_output(j.result,item.id)} for j in jobs],'safety':{'untrusted_execution':('sandboxed_execution' if any((j.result or {}).get('stages',{}).get('emulation',{}).get('authorization')=='mentor_authorized' for j in jobs) else 'controlled_or_static_only'),'raw_reveal':'disabled'},'limitations':['Firmware images receive bounded execution and symbolic checks; startup success does not establish full service coverage.','Unknown path components are pseudonymized to prevent proprietary-string disclosure.','Symbolic findings are bounded candidates for human review.']}

@api.get('/',include_in_schema=False)
def dashboard():
    return FileResponse(Path(__file__).parent/'ui'/'index.html',headers={'Cache-Control':'no-store','Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'"})

api.mount('/assets',StaticFiles(directory=Path(__file__).parent/'ui'),name='assets')


def friendly_name(item):
    return item.provenance.get('display_name') or ('Sample firmware' if item.provenance.get('kind')=='controlled_fixture' else 'Firmware analysis')

@api.post('/api/v1/firmware/{firmware_id}/name',dependencies=guard)
def rename_firmware(firmware_id:uuid.UUID,display_name:Annotated[str,Form(min_length=1,max_length=80)],db:Session=Depends(session)):
    item=firmware_or_404(db,firmware_id)
    name=display_name.strip()
    if not name:raise HTTPException(422,'Please enter a name')
    item.provenance={**item.provenance,'display_name':name}
    job_id=db.scalar(select(Job.id).where(Job.firmware_id==item.id).order_by(Job.created_at.desc()).limit(1))
    if job_id is None:raise HTTPException(409,'Analysis record is unavailable')
    db.add(AuditEvent(job_id=job_id,event='firmware_renamed',details={'firmware_id':item.id,'name_sha256':hashlib.sha256(name.encode()).hexdigest()}))
    db.commit()
    return {'firmware_id':item.id,'display_name':name}
