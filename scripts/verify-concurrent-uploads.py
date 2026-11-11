"""Real concurrent spooled uploads; no target execution and no DB cleanup."""
import concurrent.futures
import json
import threading
import time
import urllib.request
import uuid
from pathlib import Path

root = Path(__file__).resolve().parents[1]
env = dict(line.split('=', 1) for line in (root / '.env').read_text().splitlines())
base = 'http://127.0.0.1:8000'
barrier = threading.Barrier(4)
def upload(index):
    boundary = 'fwx' + uuid.uuid4().hex
    parts = []
    for key, value in {'provenance_kind': 'controlled_fixture', 'license_id': 'MIT', 'display_name': 'Concurrent upload regression ' + str(index)}.items():
        parts.append((f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n{value}\r\n').encode())
    parts.append((f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="controlled.bin"\r\n\r\n').encode() + b'\0' * (4*1024*1024) + b'\r\n')
    parts.append(f'--{boundary}--\r\n'.encode())
    request = urllib.request.Request(base + '/api/v1/firmware/upload', data=b''.join(parts), headers={'Authorization': 'Bearer ' + env['FWX_API_TOKEN'], 'Content-Type': 'multipart/form-data; boundary=' + boundary})
    barrier.wait(timeout=10)
    with urllib.request.urlopen(request, timeout=20) as response:
        assert response.status == 202
        return json.load(response)

latencies = []
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
    futures = [pool.submit(upload, i) for i in range(4)]
    while not all(f.done() for f in futures):
        start = time.monotonic()
        with urllib.request.urlopen(base + '/health', timeout=2) as response:
            assert response.status == 200
        latencies.append(time.monotonic() - start)
        time.sleep(.01)
    uploads = [f.result() for f in futures]
assert len({x['job_id'] for x in uploads}) == 4
print(json.dumps({'passed': True, 'uploads': uploads, 'health_checks': len(latencies), 'max_health_seconds': max(latencies)}, indent=2))
