"""Finding/evidence persistence boundary. Reject unredacted/free-text artifacts."""
import re
from sqlalchemy import select
from firmwarex.findings import validate
from firmwarex.models import Finding, FindingEvidence, AuditEvent

from firmwarex.diagnostic_vocabulary import WORDS,KEYS

def safe_evidence(value):
    if value is None or type(value) is bool:return
    if type(value) is int:
        if abs(value)>2**64:raise ValueError('oversized literal')
        return
    if isinstance(value,str):
        if value in WORDS or re.fullmatch(r'(?:[a-f0-9]{64}|0x[0-9a-f]+|fwx_(?:cgi_stdin|cgi_query|environment|network)_[0-9]+)',value):return
        raise ValueError('free text in diagnostic evidence')
    if isinstance(value,list):
        for child in value:safe_evidence(child)
        return
    if isinstance(value,dict):
        if set(value)-KEYS:raise ValueError('unknown evidence key')
        for child in value.values():safe_evidence(child)
        return
    raise ValueError('unsupported evidence type')

def persist(db,job_id,result):
    records=result.get('findings',[]);artifacts=result.get('evidence',{})
    for finding in records:
        validate(finding)
        if finding['sink'] not in {None,'strcpy','strcat','gets','memcpy','sprintf','system','popen'}:raise ValueError('unknown sink')
        if finding['source'] and not re.fullmatch(r'fwx_(?:cgi_stdin|cgi_query|environment|network)_[0-9]+(?:,fwx_(?:cgi_stdin|cgi_query|environment|network)_[0-9]+)*',finding['source']):raise ValueError('unknown source')
        for value in (finding['crash_state']['registers'] or {}).values():safe_evidence(value)
        detail=artifacts[finding['evidence_ref']];safe_evidence(detail)
        if detail.get('redacted') is not True:raise ValueError('unredacted evidence')
    for finding in records:
        if db.get(Finding,finding['vulnerability_id']) is None:
            db.add(Finding(id=finding['vulnerability_id'],firmware_id=finding['firmware_id'],record=finding))
        ref=finding['evidence_ref']
        if db.get(FindingEvidence,ref) is None:db.add(FindingEvidence(id=ref,artifact=artifacts[ref]))
    db.add(AuditEvent(job_id=job_id,event='findings_persisted',details={'count':len(records),'finding_ids':[f['vulnerability_id'] for f in records],'redacted':True}))
