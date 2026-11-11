"""Trusted emulation gate. Untrusted execution remains unavailable until review."""
import hashlib
import json
from pathlib import Path
from firmwarex.sandbox import launch
from uuid import UUID
from firmwarex.database import factory
from firmwarex.models import AuditEvent

def authorize(request, root, trusted_manifest):
    # The caller cannot self-label an uploaded file as a controlled fixture.
    if set(request)-{"binary","architecture","sha256","args","mode","protocol","timeout_seconds","kernel","kernel_sha256"}:
        raise PermissionError("unknown request fields")
    if request.get("mode","user") not in {"user","system","service"}:
        raise PermissionError("invalid mode")
    if request.get("protocol","http") not in {"http","mqtt","upnp"}:
        raise PermissionError("invalid protocol")
    if not isinstance(request.get("timeout_seconds",10),int) or not 1<=request.get("timeout_seconds",10)<=60:
        raise PermissionError("invalid timeout")
    manifest=json.loads(Path(trusted_manifest).read_text())
    path=(root/request["binary"]).resolve()
    if not path.is_relative_to(root.resolve()) or not path.is_file():
        raise PermissionError("invalid fixture path")
    actual=hashlib.sha256(path.read_bytes()).hexdigest()
    entry=manifest.get("fixtures",{}).get(actual)
    if not entry or entry["architecture"]!=request["architecture"] or actual!=request["sha256"]:
        raise PermissionError("binary is not a registered controlled fixture")
    if request.get("args",[]) not in entry.get("allowed_args",[[]]):
        raise PermissionError("unregistered controlled arguments")
    if request.get("kernel"):
        kernel=(root/request["kernel"]).resolve()
        if not kernel.is_relative_to(root.resolve()) or not kernel.is_file():
            raise PermissionError("unregistered kernel")
        digest=hashlib.sha256(kernel.read_bytes()).hexdigest()
        if manifest.get("kernels",{}).get(digest,{}).get("architecture")!=request["architecture"] or digest!=request.get("kernel_sha256"):
            raise PermissionError("kernel is not registered for execution")
    allowed={path}
    if request.get("kernel"): allowed.add(kernel)
    for candidate in root.rglob("*"):
        if candidate.is_symlink() or (not candidate.is_dir() and candidate.resolve() not in allowed):
            raise PermissionError("unregistered rootfs content")
    return {"authorization":"controlled_fixture_registry","sha256":actual}

def emulate(job_id, config, trusted_manifest):
    UUID(job_id)
    input_dir=config.storage/"jobs"/job_id/"input"
    request=json.loads((input_dir/"request.json").read_text())
    def audit(event, details):
        with factory()() as session:
            session.add(AuditEvent(job_id=job_id,event=event,details=details))
            session.commit()
    try:
        approval=authorize(request,input_dir/"rootfs",trusted_manifest)
    except PermissionError:
        audit("emulation_denied", {"reason":"controlled_fixture_gate"})
        raise
    audit("emulation_started", {"request":request,"approval":approval,"image":config.emulation_image,
        "quotas":{"cpu_seconds":config.job_cpu_seconds,"wall_seconds":config.job_wall_seconds,"memory_bytes":config.job_memory_bytes}})
    # Same proven quota/cleanup mechanism as static execution. No route is added.
    try:
        result,telemetry=launch(job_id,config.model_copy(update={"static_image":config.emulation_image}), scope="emulation")
    except Exception as error:
        audit("emulation_failed", {"error_type":type(error).__name__})
        raise
    audit("emulation_finished", {"result":result,"sandbox":telemetry})
    return {"result":result,"sandbox":telemetry,"authorization":approval}
