import json
import uuid
import pytest
from firmwarex.findings import normalize,validate,FIELDS
from firmwarex.scanners.secrets import scan,fingerprint
from firmwarex.persistence import safe_evidence

FID=str(uuid.uuid4());SALT=b'unit-fixture-only-salt-32-bytes-long'
PARAMS=dict(firmware_id=FID,path='/etc/controlled.conf',architecture='ARM32',salt=SALT)

def base():return normalize(firmware_id=FID,binary='/bin/fixture',architecture='ARM32',category='hardcoded_secret',cwe='CWE-798',evidence_ref='evidence:'+'a'*64)

def test_normalized_schema_and_stable_identity():
 one=base();two=base();assert set(one)==FIELDS and one['vulnerability_id']==two['vulnerability_id'];validate(one)

@pytest.mark.parametrize('field',sorted(FIELDS))
def test_missing_field_denied(field):
 value=base();del value[field]
 with pytest.raises(ValueError):validate(value)

@pytest.mark.parametrize('field,value',[('architecture','unknown'),('category','other'),('confidence','certain'),('risk_rating','severe'),('status','done'),('cwe','798'),('binary','../outside'),('address','bad'),('tainted_path',[None]),('redacted',False),('detected_at','2026-01-01'),('evidence_ref','raw-secret')])
def test_invalid_values(field,value):
 finding=base();finding[field]=value
 with pytest.raises(ValueError):validate(finding)

def test_credentials_keys_certificates_entropy_and_weak_crypto():
 payload=b'password=UnitTestPassword123\napi_key=Q7vM2xL9pR4nB8cK3sD6fH1j\n-----BEGIN PRIVATE KEY-----\nSYNTHETIC-NOT-A-REAL-KEY\n-----END PRIVATE KEY-----\n-----BEGIN CERTIFICATE-----\nSYNTHETIC-CERTIFICATE\n-----END CERTIFICATE-----\nauthentication_hash=md5\nlegacy_cipher=rc4\nblob=H5nZ2wC8qR4mA7vJ3xL9tB6k\n'
 result=scan(payload,**PARAMS);rules={e['rule'] for e in result['evidence'].values()}
 assert rules=={'credential','private_key','security_weak_crypto'}
 assert result['observations']['certificates']==1
 assert result['observations']['entropy_candidates']>=1
 encoded=json.dumps(result).encode()
 for value in [b'UnitTestPassword123',b'Q7vM2xL9pR4nB8cK3sD6fH1j',b'SYNTHETIC-NOT-A-REAL-KEY',b'SYNTHETIC-CERTIFICATE',b'H5nZ2wC8qR4mA7vJ3xL9tB6k']:assert value not in encoded
 for finding in result['findings']:validate(finding)
 for detail in result['evidence'].values():safe_evidence(detail)

def test_benign_checksum_and_low_entropy_are_not_crypto_findings():
 result=scan(b'checksum=md5\nblob=AAAAAAAAAAAAAAAAAAAAAAAAAAA\nversion=1.2.3',**PARAMS)
 assert not result['findings']

def test_salts_and_repeated_value():
 value=b'fake-example-only'
 assert fingerprint(value,SALT)==fingerprint(value,SALT)
 assert fingerprint(value,SALT)!=fingerprint(value,b'other-unit-salt-at-least-32-bytes-long')
 with pytest.raises(ValueError):fingerprint(value,b'short')

def test_scan_budget_is_incomplete():
 assert scan(b'x'*10,**PARAMS,max_bytes=5)['status']=='incomplete'

@pytest.mark.parametrize('artifact',[{'raw':'never persist this'},{'rule':'untrusted text'},{'constant':2**256}])
def test_raw_evidence_denied(artifact):
 with pytest.raises(ValueError):safe_evidence(artifact)

def test_proprietary_content_and_keys_redacted():
 from firmwarex.redaction import redact_content
 value={'proprietary-example': ['secret-value',b'private-bytes']}
 encoded=json.dumps(redact_content(value,SALT))
 for needle in ['proprietary-example','secret-value','private-bytes']:assert needle not in encoded
 assert 'fingerprint' in encoded

@pytest.mark.parametrize('algorithm,cwe',[(b'md5','CWE-328'),(b'sha-1','CWE-328'),(b'des','CWE-327'),(b'rc4','CWE-327')])
def test_required_weak_crypto_contexts(algorithm,cwe):
 result=scan(b'authentication_cipher='+algorithm,**PARAMS)
 assert len(result['findings'])==1 and result['findings'][0]['cwe']==cwe
