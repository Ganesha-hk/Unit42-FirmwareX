"""Real HTTP/queue/PostgreSQL/sandbox integration; no firmware execution."""
import json
import time
from pathlib import Path
import urllib.request
import urllib.error
import uuid

root = Path(__file__).resolve().parents[1]
env = dict(line.split("=", 1) for line in (root / ".env").read_text().splitlines())
base = "http://127.0.0.1:8000"
headers = {"Authorization": "Bearer " + env["FWX_API_TOKEN"]}
evidence = {"cases": [], "scope": "static_only"}

def get(path):
    with urllib.request.urlopen(urllib.request.Request(base + path, headers=headers), timeout=15) as response:
        return json.load(response)

def upload(path):
    boundary = "fwx" + uuid.uuid4().hex
    parts = []
    for key, value in {"provenance_kind": "controlled_fixture", "license_id": "MIT"}.items():
        parts.append((f"--{boundary}\r\nContent-Disposition: form-data; name=\"{key}\"\r\n\r\n{value}\r\n").encode())
    parts.append((f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{path.name}\"\r\nContent-Type: application/octet-stream\r\n\r\n").encode() + path.read_bytes() + b"\r\n")
    parts.append(f"--{boundary}--\r\n".encode())
    request = urllib.request.Request(base + "/api/v1/firmware/upload", data=b"".join(parts),
        headers={**headers, "Content-Type": "multipart/form-data; boundary=" + boundary}, method="POST")
    with urllib.request.urlopen(request, timeout=30) as response:
        assert response.status == 202
        return json.load(response)

for name in ["cramfs.bin", "jffs2.bin", "ubifs.bin", "cpio.bin", "ext.bin"]:
    expected = "static_complete"
    submitted = upload(root / "work/fixtures/formats" / name)
    deadline = time.monotonic() + 240
    while True:
        job = get("/api/v1/jobs/" + submitted["job_id"])
        if job["status"] not in {"queued", "running"}: break
        if time.monotonic() > deadline: raise AssertionError("job timeout")
        time.sleep(1)
    assert job["status"] == expected, job
    firmware_id = submitted["firmware_id"]
    summary = get("/api/v1/firmware/" + firmware_id)
    files = get("/api/v1/firmware/" + firmware_id + "/filesystem")
    binaries = get("/api/v1/firmware/" + firmware_id + "/binary-audit")
    assert summary["sha256"] == submitted["sha256"]
    if expected == "static_complete":
        assert len(binaries["binaries"]) == 4
        assert any(f["path"] == "/etc/fixture.txt" for f in files["files"])
    evidence["cases"].append({"name": name, "upload": submitted, "job": job, "filesystem": files, "binary_audit": binaries})

(root / "evidence/day1/format-integration.json").write_text(json.dumps(evidence, indent=2) + "\n")
print("PASS: five additional filesystem formats")
