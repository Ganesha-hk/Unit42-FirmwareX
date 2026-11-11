"""All content matches leave the scanner only as salted fingerprints."""
import hashlib
import hmac
import math
import re
from collections import Counter
from firmwarex.findings import normalize

ASSIGNMENT=re.compile(rb'(?i)\b(api[_-]?key|access[_-]?token|password|passwd|secret|credential)\s*[:=]\s*[\"\']?([^\x00-\x20\"\'<>;,]{4,256})')
PEM=re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?(PRIVATE KEY|CERTIFICATE)-----[\s\S]{1,65536}?-----END [A-Z ]+-----')
TOKEN=re.compile(rb'[A-Za-z0-9_+/=-]{24,256}')
WEAK=re.compile(rb'(?i)\b(md5|sha[-_]?1|des|rc4)\b')
SECURITY=re.compile(rb'(?i)password|signature|authentication|authenticate|crypto|cipher|encrypt|credential|hmac')

def fingerprint(value,salt):
    if not isinstance(salt,bytes) or len(salt)<32: raise ValueError('32-byte private salt required')
    return hmac.new(salt,value,hashlib.sha256).hexdigest()

def entropy(data):
    return -sum((n/len(data))*math.log2(n/len(data)) for n in Counter(data).values()) if data else 0

def scan(data,*,firmware_id,path,architecture,salt,max_bytes=16*1024*1024):
    if len(data)>max_bytes:return {'status':'incomplete','reason':'file_size_budget','findings':[],'evidence':{}}
    hits=[]; observations={'entropy_candidates':0,'certificates':0}
    # NUL is a string boundary in ELF data. A whole binary is not one line of
    # security context. Bound records even for malformed or minified inputs.
    def context(start,end):
        left=max(data.rfind(b'\n',0,start),data.rfind(b'\x00',0,start),start-96)+1
        ends=[n for n in (data.find(b'\n',end),data.find(b'\x00',end),end+96) if n>=0]
        return data[left:min(ends)]
    def literal(value):
        return not (value.lower() in {b'undefined',b'null',b'none',b'true',b'false'} or
                    any(c in value for c in (b'$',b'%',b'(',b')',b'{',b'}',b'\\')))

    for match in ASSIGNMENT.finditer(data):
        if not literal(match.group(2)):continue
        hits.append((match.start(2),match.end(2),'credential','CWE-259' if match.group(1).lower() in {b'password',b'passwd'} else 'CWE-798',match.group(2),'hardcoded_secret','probable'))
    for match in PEM.finditer(data):
        if match.group(1)==b'CERTIFICATE':
            observations['certificates']+=1
            continue  # Public certificates are not hardcoded private keys.
        hits.append((match.start(),match.end(),'private_key','CWE-321',match.group(),'hardcoded_secret','heuristic'))
    for match in TOKEN.finditer(data):
        value=match.group()
        if entropy(value)>=4.2 and not any(a<match.end() and match.start()<b for a,b,*_ in hits):
            observations['entropy_candidates']+=1
            # Entropy alone cannot distinguish a secret from a symbol, resource
            # name, compressed data, hash, or public key.
            record=context(match.start(),match.end())
            if re.search(rb'(?i)\b(api[_-]?key|access[_-]?token|password|passwd|secret|credential)\b',record) and literal(value):
                hits.append((match.start(),match.end(),'high_entropy','CWE-798',value,'hardcoded_secret','heuristic'))
    for match in WEAK.finditer(data):
        line=context(match.start(),match.end())
        if SECURITY.search(line):hits.append((match.start(),match.end(),'security_weak_crypto','CWE-328' if match.group().lower().replace(b'-',b'').replace(b'_',b'') in {b'md5',b'sha1'} else 'CWE-327',line,'weak_crypto','heuristic'))
    findings=[];evidence={}
    for start,end,rule,cwe,value,category,confidence in hits:
        digest=fingerprint(value,salt)
        ref='evidence:'+fingerprint((path+':'+str(start)+':'+rule+':'+digest).encode(),salt)
        evidence[ref]={'rule':rule,'byte_offset':start,'byte_length':end-start,'fingerprint':digest,'redacted':True,'heuristic':confidence=='heuristic'}
        findings.append(normalize(firmware_id=firmware_id,binary=path,architecture=architecture,category=category,cwe=cwe,evidence_ref=ref,confidence=confidence,risk_rating='low' if rule in {'certificate','high_entropy'} else 'medium'))
    return {'status':'completed','findings':list({f['vulnerability_id']:f for f in findings}.values()),'evidence':evidence,'observations':observations}
