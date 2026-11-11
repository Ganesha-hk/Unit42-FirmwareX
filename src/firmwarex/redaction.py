"""Fail-closed content redaction for future display/export integrations."""
from firmwarex.scanners.secrets import fingerprint

def redact_content(value,salt):
    """Do not infer which arbitrary firmware strings are safe or proprietary."""
    if isinstance(value,(str,bytes)):
        raw=value.encode() if isinstance(value,str) else value
        return {'redacted':True,'fingerprint':fingerprint(raw,salt),'byte_length':len(raw)}
    if isinstance(value,list):return [redact_content(item,salt) for item in value]
    if isinstance(value,dict):
        # Keys can also contain secrets. Preserve shape without preserving raw names.
        return [{'key':redact_content(str(key),salt),'value':redact_content(item,salt)} for key,item in value.items()]
    return value

def deny_reveal(db,job_id,actor_id):
    """No raw reveal capability is enabled before an authorization model exists."""
    from firmwarex.models import AuditEvent
    from uuid import UUID
    UUID(job_id);UUID(actor_id)
    db.add(AuditEvent(job_id=job_id,event='raw_reveal_denied',details={'actor_id':actor_id,'reason':'raw_reveal_disabled'}))
    db.commit()
    raise PermissionError('Raw artifact reveal is disabled')
