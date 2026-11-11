"""Appendix A normalization and strict validation; no guest text is copied implicitly."""
from datetime import datetime, timezone
import re
from uuid import UUID, uuid5, NAMESPACE_URL

ARCHITECTURES = {'ARM32','ARM64','MIPS','MIPSEL','x86_64'}
CATEGORIES = {'memory_corruption','hardcoded_secret','weak_crypto','missing_mitigation','command_injection'}
FINDING_ENUMS = {
    'architecture': ARCHITECTURES,
    'category': CATEGORIES,
    'risk_rating': {'critical', 'high', 'medium', 'low', 'info'},
    'confidence': {'confirmed', 'probable', 'heuristic'},
    'status': {'new', 'triaged', 'validated', 'false_positive'},
}
FIELDS = {'vulnerability_id','firmware_id','binary','architecture','category','cwe','address','sink','source','tainted_path','crash_state','risk_rating','confidence','evidence_ref','redacted','status','detected_at'}
CRASH_FIELDS = {'fault_address','registers','overflow_offset','stack_hash'}
HEX = re.compile(r'^0x[0-9a-f]+$')

def validate(finding):
    if set(finding) != FIELDS: raise ValueError('finding fields')
    for name in ('firmware_id','vulnerability_id'): UUID(finding[name])
    for name,values in FINDING_ENUMS.items():
        if finding[name] not in values: raise ValueError(name)
    if not isinstance(finding['binary'],str) or not finding['binary'].startswith('/') or '..' in finding['binary'].split('/'): raise ValueError('binary')
    if not re.fullmatch(r'CWE-[0-9]+',finding['cwe']): raise ValueError('cwe')
    for name in ('sink','source'):
        if finding[name] is not None and not isinstance(finding[name],str): raise ValueError(name)
    if not isinstance(finding['tainted_path'],list): raise ValueError('path')
    if any(not isinstance(a,str) or not HEX.fullmatch(a) for a in finding['tainted_path']):raise ValueError('path address')
    for address in [finding['address'],*finding['tainted_path']]:
        if address is not None and (not isinstance(address,str) or not HEX.fullmatch(address)): raise ValueError('address')
    crash=finding['crash_state']
    if not isinstance(crash,dict) or set(crash)!=CRASH_FIELDS: raise ValueError('crash_state')
    if crash['fault_address'] is not None and not HEX.fullmatch(crash['fault_address']): raise ValueError('fault address')
    if crash['registers'] is not None and not isinstance(crash['registers'],dict): raise ValueError('registers')
    if crash['overflow_offset'] is not None and (type(crash['overflow_offset']) is not int or crash['overflow_offset']<0): raise ValueError('offset')
    if crash['stack_hash'] is not None and not re.fullmatch('[a-f0-9]{64}',crash['stack_hash']): raise ValueError('stack hash')
    if type(finding['redacted']) is not bool or not finding['redacted']: raise ValueError('unredacted finding denied')
    if not re.fullmatch(r'evidence:[a-f0-9]{64}',finding['evidence_ref']): raise ValueError('evidence reference')
    stamp=finding['detected_at']
    if not stamp.endswith('Z'): raise ValueError('timestamp UTC required')
    datetime.fromisoformat(stamp.replace('Z','+00:00'))
    return finding

def normalize(*,firmware_id,binary,architecture,category,cwe,evidence_ref,address=None,sink=None,source=None,tainted_path=None,crash_state=None,risk_rating='medium',confidence='heuristic'):
    identity='|'.join([firmware_id,binary,category,cwe,address or '',sink or '',source or '',evidence_ref])
    return validate(dict(vulnerability_id=str(uuid5(NAMESPACE_URL,identity)),firmware_id=firmware_id,binary=binary,architecture=architecture,category=category,cwe=cwe,address=address,sink=sink,source=source,tainted_path=tainted_path or [],crash_state=crash_state or dict(fault_address=None,registers=None,overflow_offset=None,stack_hash=None),risk_rating=risk_rating,confidence=confidence,evidence_ref=evidence_ref,redacted=True,status='new',detected_at=datetime.now(timezone.utc).isoformat().replace('+00:00','Z')))
