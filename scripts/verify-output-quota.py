"""Benign storage/serialization probes under the production sandbox profile."""
import io
import json
import os
import tarfile
import uuid
from pathlib import Path
import docker
from firmwarex.config import settings
from firmwarex.sandbox import launch, OUTPUT_BYTES

programs = {
    'redaction': "import json; from pathlib import Path; Path('/output/result.json').write_text(json.dumps({'schema_version':1,'description':'synthetic-private-sentinel','private-field':'synthetic-private-sentinel'}))",
    'bytes': '''import errno,json
from pathlib import Path
size=0
try:
 for i in range(80):
  Path('/output/block-'+str(i)).write_bytes(b'x'*(1024*1024));size+=1024*1024
except OSError as e:assert e.errno==errno.ENOSPC
else:raise AssertionError('byte quota missing')
for p in Path('/output').iterdir():p.unlink()
Path('/output/result.json').write_text(json.dumps({'schema_version':1,'bytes_before_denial':size}))
''',
    'inodes': '''import errno,json
from pathlib import Path
count=0
try:
 for i in range(1100):Path('/output/file-'+str(i)).touch();count+=1
except OSError as e:assert e.errno==errno.ENOSPC
else:raise AssertionError('inode quota missing')
for p in Path('/output').iterdir():p.unlink()
Path('/output/result.json').write_text(json.dumps({'schema_version':1,'files_before_denial':count}))
''',
    'oversized': "from pathlib import Path; Path('/output/result.json').write_bytes(b'x'*(33*1024*1024))",
    'symlink': "from pathlib import Path; Path('/output/result.json').symlink_to('/input/private')",
    'malformed': "from pathlib import Path; Path('/output/result.json').write_text('not json')",
}
client = docker.from_env()
base = settings()
results = []
try:
    for mode, program in programs.items():
        if os.environ.get('FWX_OUTPUT_CASE') and mode != os.environ['FWX_OUTPUT_CASE']:
            continue
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode='w') as tar:
            for name, content in {'Dockerfile': 'FROM firmwarex-control:day1\nCOPY probe.py /probe.py\nENTRYPOINT ["python", "/probe.py"]\nCMD []\n', 'probe.py': program}.items():
                data = content.encode(); member = tarfile.TarInfo(name); member.size = len(data)
                tar.addfile(member, io.BytesIO(data))
        archive.seek(0)
        tag = 'firmwarex-output-' + mode + ':test'
        client.images.build(fileobj=archive, custom_context=True, tag=tag, rm=True)
        job = str(uuid.uuid4()); folder = base.storage / 'jobs' / job / 'input'
        folder.mkdir(parents=True); (folder / 'private').write_text('synthetic-private-sentinel')
        result, telemetry = launch(job, base.model_copy(update={'static_image': tag, 'job_memory_bytes': 128*1024*1024, 'job_wall_seconds': 20}), scope='pipeline')
        import sys
        print(json.dumps({'case': mode, 'result': result, 'sandbox': telemetry}), file=sys.stderr, flush=True)
        if mode == 'redaction':
            assert result.get('schema_version') == 1 and 'synthetic-private-sentinel' not in json.dumps(result)
            assert json.loads((folder.parent/'output/result.json').read_text()) == result
        elif mode == 'bytes':assert 0 < result['bytes_before_denial'] <= OUTPUT_BYTES
        elif mode == 'inodes':assert 0 < result['files_before_denial'] < 1024
        else:assert result == {'error_code': 'invalid_output'}, (mode, result)
        output = folder.parent / 'output'
        assert {p.name for p in output.iterdir()} <= {'result.json'}
        assert all('synthetic-private-sentinel' not in p.read_text() for p in output.iterdir())
        assert not client.containers.list(all=True, filters={'label': 'firmwarex.job_id=' + job})
        assert not client.volumes.list(filters={'label': 'firmwarex.job_id=' + job})
        results.append({'case': mode, 'passed': True, 'result': result, 'sandbox': telemetry, 'cleanup_verified': True})
finally:
    client.close()
print(json.dumps(results, indent=2))
