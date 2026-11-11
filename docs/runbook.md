# Local FirmwareX runbook

Use Docker/Compose on the recorded Ubuntu x86_64 host. Application Python is isolated 3.12; do not install analysis dependencies into system Python. Build prerequisites and fixture details are in day1-validation.md, task3-review.md and task4-review.md. Native package sources, image digests and Python wheel hashes are locked in infra/images and locks.

## Build and start

On an existing prepared checkout, preserve `.env` and `.runtime`:

```sh
docker build -f infra/images/control/Dockerfile -t firmwarex-control:day1 .
docker build -f infra/images/pipeline/Dockerfile -t firmwarex-pipeline:task5 .
docker compose up -d
```

On a fresh checkout, first run `python3 scripts/bootstrap.py` once to create ignored local credentials/storage. Build the native/static/QEMU images and analysis/emulation fixtures using the earlier milestone instructions before building the pipeline image; it derives from `firmwarex-qemu:task3`. The pipeline fixture builder runs in the compiler image with work/fixtures at /fixtures and fixtures/manifests at /manifests. It combines the existing compiled analysis and emulation fixtures; review any exact-registry hash changes. A clean independent full rebuild remains a Task 6 acceptance test.

Wait for `http://127.0.0.1:8000/health` to respond; Compose container start alone does not establish API readiness. Open `http://127.0.0.1:8000/` and enter FWX_API_TOKEN from the local `.env`. The browser holds it only in memory. PostgreSQL/Redis have no host ports. Only the trusted dispatcher has the Docker socket. Never expose this development deployment directly to untrusted users.

## Submit and inspect

The dashboard upload form accepts licensed image files and provenance. Only an exact controlled image in the built registry can execute. Other images receive static/scanner processing and explicit blocked execution stages. Full vendor support is not implied by a complete controlled job.

All seven routes require Bearer authentication. Interactive schemas and requests are available at `/docs`:

```sh
# Set FWX_API_TOKEN privately in your terminal; do not place a real token in reports.
curl -H "Authorization: Bearer $FWX_API_TOKEN" \
  -F file=@work/fixtures/controlled-pipeline.bin \
  -F provenance_kind=controlled_fixture -F license_id=MIT \
  http://127.0.0.1:8000/api/v1/firmware/upload
# Use returned UUIDs for the following placeholders:
curl -H "Authorization: Bearer $FWX_API_TOKEN" http://127.0.0.1:8000/api/v1/jobs/JOB_UUID
curl -H "Authorization: Bearer $FWX_API_TOKEN" http://127.0.0.1:8000/api/v1/firmware/FIRMWARE_UUID
curl -H "Authorization: Bearer $FWX_API_TOKEN" http://127.0.0.1:8000/api/v1/firmware/FIRMWARE_UUID/filesystem
curl -H "Authorization: Bearer $FWX_API_TOKEN" http://127.0.0.1:8000/api/v1/firmware/FIRMWARE_UUID/binary-audit
curl -H "Authorization: Bearer $FWX_API_TOKEN" http://127.0.0.1:8000/api/v1/firmware/FIRMWARE_UUID/vulnerabilities
curl -H "Authorization: Bearer $FWX_API_TOKEN" http://127.0.0.1:8000/api/v1/firmware/FIRMWARE_UUID/report
```

Upload returns firmware_id, job_id, sha256 and queued status. Actual full responses are in evidence/task5/controlled-report.json and gated-report.json. The automated HTTP verifier executes equivalent requests. Jobs progress queued → running → complete/partial/failed. `complete` concerns the selected bounded pipeline, not proof of exhaustive analysis or final PRD compliance. Earlier static-only historical statuses remain visible.

Use File explorer for metadata, Binary hardening for mitigation/risk sorting, Findings for candidates/evidence, Control-flow graph for selected functions/taint, and Job telemetry for local OpenTelemetry records. Download report exports the authenticated redacted JSON. Raw input/rootfs downloads are intentionally unavailable.

## Verify

```sh
python3 scripts/verify-pipeline.py
python3 scripts/verify-task5-api-guards.py
docker compose run --rm --no-deps -v "$PWD/scripts:/scripts:ro" -v "$PWD/evidence/task5:/evidence" dispatcher python /scripts/verify-task5-storage.py
docker compose run --rm --no-deps -e FWX_TEST_SCOPE=pipeline -v "$PWD/scripts:/scripts:ro" dispatcher python /scripts/verify-quotas.py
```

Browser automation uses Node and Playwright/Chromium. Install the pinned test dependency in a separate tools directory (`npm install --prefix work/browser-tools playwright@1.62.1`, then `work/browser-tools/node_modules/.bin/playwright install chromium`). Set `FWX_PLAYWRIGHT_MODULE` to the absolute `work/browser-tools/node_modules/playwright` directory before running the browser scripts, or make `playwright` resolvable by Node. No developer-home path is hard-coded. `FWX_EVIDENCE_DIR` selects a fresh output directory for pipeline, API, dashboard and readable-report checks. An independent clean-machine reproduction is still required.

For a moved checkout, update only `FWX_HOST_STORAGE`, `FWX_SANDBOX_UID` and `FWX_SANDBOX_GID` in the private `.env` to the actual storage path and owning user/group, then recreate the Compose services. Preserve credentials and existing data. Use your actual UID/GID for test-container evidence mounts; do not assume 1000. The runtime needs Docker local-driver tmpfs volumes and container pause support for bounded artifact collection.

## Operations and shutdown

One heavy job runs at once. Admission returns 429 at 16 queued/running jobs. Redis failures retain durable queued rows for scheduler redispatch; abandoned jobs fail after the recovery lease. Review status/error code before retrying failed jobs. Analysis logs are disabled; reports contain fixed diagnostic codes and sanitized evidence.

`docker compose down` stops services while retaining volumes and `.runtime`. Do not use `down -v`, erase raw storage, or remove databases without intentional deletion authorization. `.runtime` contains protected source images and salts; it is not a shareable report directory. No push, publication or merge without user approval.
