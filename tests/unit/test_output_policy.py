from firmwarex.output_policy import safe_path,sanitize_inventory
SALT=b'controlled-unit-salt-32-bytes-long'
def test_unknown_names_are_stable_pseudonyms():
 path='/etc/proprietary-secret-name'
 result=safe_path(path,SALT)
 assert result.startswith('/etc/redacted-') and 'proprietary' not in result
 assert result==safe_path(path,SALT)
def test_nested_structure_preserved():
 assert safe_path('/usr/bin/service-probe',SALT)=='/usr/bin/service-probe'
 assert safe_path('/vendor/private',SALT).count('/')==2
def test_inventory_dynamic_arch_and_device_text_not_exported():
 files=[{'path':'/dev/vendor','device':'sensitive'}];bins=[{'path':'/bin/vendor','architecture':'vendor-secret'}]
 f,b,e=sanitize_inventory(files,bins,[],SALT)
 assert f[0]['device']=='redacted-device-metadata' and b[0]['architecture']=='unsupported'

def test_output_filter_redacts_unknown_keys_values_and_is_idempotent():
 from firmwarex.output_policy import sanitize_output
 value={'errors':[{'path':'/etc/PRIVATE-PATH','code':'PRIVATE-ERROR'}], 'PRIVATE-KEY':'PRIVATE-CONTENT','graphs':{'/bin/PRIVATE-NAME':{'functions':[]}},'fingerprint':'a'*64,'trace_id':'b'*32}
 safe=sanitize_output(value,SALT)
 assert 'PRIVATE-' not in str(safe)
 assert safe['fingerprint']=='a'*64 and safe['trace_id']=='b'*32
 assert sanitize_output(safe,SALT)==safe

def test_hex_looking_secret_not_preserved_in_untyped_fields():
 from firmwarex.output_policy import sanitize_output
 secret='a'*64
 assert secret not in str(sanitize_output({'description':secret,'password':secret},SALT))

def test_paths_and_taint_source_preserve_structure():
 from firmwarex.output_policy import sanitize_output
 value={'binary':'/bin/taint-demo','source':'fwx_cgi_stdin_0','tainted_path':['0x401000'],'evidence_ref':'evidence:'+'a'*64}
 assert sanitize_output(value,SALT)==value

def test_runtime_normal_control_field_is_preserved_for_saved_evidence():
 from firmwarex.output_policy import sanitize_output
 value={'normal_request':'http_200_marker_verified','cve':'CVE-2019-19945','sink':'client_poll_post_data'}
 assert sanitize_output(value,SALT)==value

def test_guest_report_is_sanitized_at_the_trusted_boundary(tmp_path):
 """A worker that forgets to sanitize cannot persist plaintext output."""
 from firmwarex.sandbox import sanitize_sandbox_result
 raw={'schema_version':1,'description':'GUEST-PRIVATE-SENTINEL','PRIVATE-KEY':'GUEST-PRIVATE-SENTINEL'}
 safe,encoded=sanitize_sandbox_result(raw,SALT)
 assert 'GUEST-PRIVATE-SENTINEL' not in str(safe)
 assert b'GUEST-PRIVATE-SENTINEL' not in encoded
 assert safe['schema_version']==1

def test_standalone_output_salt_is_private_and_stable(tmp_path):
 from firmwarex.sandbox import output_salt
 salt=output_salt(tmp_path)
 assert len(salt)==32 and output_salt(tmp_path)==salt
 assert (tmp_path/'fingerprint-salt').stat().st_mode & 0o777 == 0o600

def test_existing_firmware_salt_is_preserved(tmp_path):
 from firmwarex.sandbox import output_salt
 (tmp_path/'fingerprint-salt').write_bytes(b'x'*32)
 assert output_salt(tmp_path)==b'x'*32

def test_invalid_or_linked_salt_is_rejected(tmp_path):
 import pytest
 from firmwarex.sandbox import output_salt
 path=tmp_path/'fingerprint-salt'
 path.write_bytes(b'short')
 with pytest.raises(ValueError):output_salt(tmp_path)
 path.unlink()
 target=tmp_path/'private';target.write_bytes(b'x'*32)
 path.symlink_to(target)
 with pytest.raises(OSError):output_salt(tmp_path)
