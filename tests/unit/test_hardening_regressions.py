import io
import json
import tarfile
from types import SimpleNamespace
from uuid import uuid4

import pytest

from firmwarex.findings import FINDING_ENUMS, normalize, validate
from firmwarex.output_policy import sanitize_output
from firmwarex.sandbox import read_container_file

SALT = b'controlled-regression-salt-32-bytes'


@pytest.mark.parametrize('field,value', [
    (field, value) for field, values in FINDING_ENUMS.items() for value in sorted(values)
])
def test_all_finding_enums_survive_output_boundary(field, value):
    finding = normalize(firmware_id=str(uuid4()), binary='/bin/taint-demo',
                        architecture='ARM32', category='hardcoded_secret',
                        cwe='CWE-798', evidence_ref='evidence:' + 'a' * 64)
    finding[field] = value
    validate(finding)
    safe = sanitize_output(finding, SALT)
    assert safe[field] == value
    validate(safe)
    assert sanitize_output(safe, SALT) == safe


def guest_archive(kind='file', size=2, second=False):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as tar:
        member = tarfile.TarInfo('result.json')
        if kind == 'symlink':
            member.type = tarfile.SYMTYPE
            member.linkname = '/input/private'
        elif kind == 'hardlink':
            member.type = tarfile.LNKTYPE
            member.linkname = '/input/private'
        else:
            member.size = size
        tar.addfile(member, io.BytesIO(b'x' * size) if kind == 'file' else None)
        if second:
            tar.addfile(tarfile.TarInfo('extra'))
    return SimpleNamespace(get_archive=lambda path: (iter([stream.getvalue()]), {'size': size}))


@pytest.mark.parametrize('kind', ['symlink', 'hardlink'])
def test_output_links_rejected(kind):
    with pytest.raises(ValueError):
        read_container_file(guest_archive(kind), '/output/result.json', 10)


def test_output_archive_limits():
    with pytest.raises(ValueError):
        read_container_file(guest_archive(size=11), '/output/result.json', 10)
    with pytest.raises(ValueError):
        read_container_file(guest_archive(second=True), '/output/result.json', 10)
    assert read_container_file(guest_archive(), '/output/result.json', 10) == b'xx'


def test_pipeline_preserves_static_and_scanner_after_target_failures(tmp_path, monkeypatch):
    import sys
    import firmwarex.pipeline as pipeline
    from firmwarex.observability import Observer
    from firmwarex.scanners.secrets import scan
    from pathlib import Path

    root = tmp_path / 'rootfs'
    root.mkdir()
    config = root / 'controlled.conf'
    config.write_bytes(b'password=SyntheticRegressionPassword123')
    image = b'controlled-test-image'
    fid, jid = str(uuid4()), str(uuid4())
    files = [{'path': '/controlled.conf', 'type': 'file', 'size': config.stat().st_size, 'hash': 'a' * 64}]
    binaries = [{'path': '/bin/taint-demo', 'architecture': 'ARM32', 'banned_functions': []}]
    original_read_bytes, original_read_text = Path.read_bytes, Path.read_text
    def read_bytes(path):
        if str(path) == '/input/firmware.bin':return image
        if str(path) == '/input/fingerprint-salt':return SALT
        return original_read_bytes(path)
    def read_text(path, *args, **kwargs):
        if str(path) == '/input/context.json':return json.dumps({'firmware_id': fid, 'job_id': jid})
        if str(path) == '/app/pipeline-controlled.json':
            import hashlib
            return json.dumps({'images': {hashlib.sha256(image).hexdigest(): {
                'emulation': [{'binary': 'missing'}],
                'symbolic': [{'binary': 'missing', 'sha256': '0' * 64, 'architecture': 'ARM32'}]}}})
        return original_read_text(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'read_bytes', read_bytes)
    monkeypatch.setattr(Path, 'read_text', read_text)
    monkeypatch.setattr(pipeline, 'unpack', lambda *args: (root, {'status': 'extracted', 'filesystems': []}))
    monkeypatch.setattr(pipeline, 'entropy', lambda *args: [])
    monkeypatch.setattr(pipeline, 'inventory', lambda *args: (files, binaries, []))
    monkeypatch.setitem(sys.modules, 'firmwarex.analysis.engine', SimpleNamespace(analyze=lambda *a, **kw: None))
    observer = Observer(jid)
    try:
        result = pipeline.run(observer)
    finally:
        observer.close()
    assert result['status'] == 'partial'
    assert result['files'] and result['binaries']
    assert result['stages']['emulation']['status'] == 'incomplete'
    assert len(result['stages']['emulation']['executions']) == 4
    assert result['stages']['symbolic']['status'] == 'incomplete'
    assert result['stages']['secrets_crypto']['status'] == 'completed'
    assert any(f['category'] == 'hardcoded_secret' for f in result['findings'])
    assert 'SyntheticRegressionPassword123' not in json.dumps(result)
