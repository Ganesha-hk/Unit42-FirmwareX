# Controlled cross-architecture end-to-end validation

Date: 20 October 2026. **PASS for all five tested architectures.**

FirmwareX completed the controlled end-to-end analysis pipeline on x86_64, ARM32, ARM64, MIPS and MIPSEL firmware fixtures.

Each image was uploaded through the production HTTP API and processed by the normal queue, sandbox and analyzers. Reports were exported from the actual dashboard using its existing renderer, not assembled from component summaries. No finding was hard-coded; no real/vendor/untrusted firmware was dynamically executed.

| Architecture | Result | Pipeline | Endianness | Findings | Software report |
| --- | --- | --- | --- | --- | --- |
| x86_64 | PASS | complete | little | 17 | [PDF](../evidence/cross-e2e/x86_64-report.pdf) / [JSON](../evidence/cross-e2e/x86_64-report.json) |
| ARM32 | PASS | complete | little | 16 | [PDF](../evidence/cross-e2e/ARM32-report.pdf) / [JSON](../evidence/cross-e2e/ARM32-report.json) |
| ARM64 | PASS | complete | little | 16 | [PDF](../evidence/cross-e2e/ARM64-report.pdf) / [JSON](../evidence/cross-e2e/ARM64-report.json) |
| MIPS | PASS | complete | big | 16 | [PDF](../evidence/cross-e2e/MIPS-report.pdf) / [JSON](../evidence/cross-e2e/MIPS-report.json) |
| MIPSEL | PASS | complete | little | 16 | [PDF](../evidence/cross-e2e/MIPSEL-report.pdf) / [JSON](../evidence/cross-e2e/MIPSEL-report.json) |

The x86_64 image yielded a modeled CWE-787 memory-safety candidate; the other four yielded modeled CWE-78 taint-to-command-sink candidates. All five also produced static-symbol and fake-secret/crypto scanner findings. Candidates retain recorded heuristic/probable confidence, not confirmed vendor exploitability.

## Required evidence

All paths below are relative to `evidence/cross-e2e/`.

| Requested proof | Saved evidence and checks |
| --- | --- |
| Fixture hash | `pipeline-results.json` contains every image SHA-256; `fixture-build.json` records four new images, target binary/source hashes and identical repeat-build hashes. |
| Extraction/inventory | Each architecture report records extracted SquashFS, six filesystem entries and two ELF binaries. |
| Architecture/endianness | Both ELF records match the expected architecture; MIPS is big-endian, the other four little-endian. |
| Mitigations | Each binary records NX, PIE, RELRO, canary, FORTIFY, bitness and limitations. Missing protections are recorded as observed, not forced to pass. |
| Actual QEMU execution | Successful benign binary run plus HTTP/UPnP/MQTT private-loopback probes; output/response hashes, sizes and architecture retained. |
| Symbolic/taint | Completed bounded analysis with budgets, tainted path, reaching-condition evidence, CWE and confidence in each report. |
| Secret redaction/fingerprinting | Salted fingerprints; plaintext sentinels absent from persisted records, artifacts, audit, API, HTML and PDF. |
| Normalized findings/persistence | `storage-results.json` verifies all 81 findings, schema, database records, evidence, output hashes and six stage audit events per job. |
| Final status/traces | `pipeline-results.json`: all complete; each report has 11 linked spans and actual sandbox telemetry. |
| Software report/dashboard | `browser-results.json`: actual uploaded-image selection, architecture matrix, CFG, telemetry, finding count, HTML download and print-to-PDF. `pdf-verification.json`: 86 pages rendered and visually reviewed across five PDFs. |
| Sandbox/quotas | Per-job telemetry records network none, read-only root, capabilities dropped, UID, CPU/memory/PID limits; cleanup verified. `quotas.json`: fresh CPU/memory/wall termination and network/host-isolation tests under the shared production pipeline profile. |
| Regression/logs | `unit-tests.xml`: 85 pass, no failures/errors/skips. `regression/`: x86 complete and unregistered controlled fixture partial/denied, eight API guards and dashboard/export/mobile pass. Build/execution/browser logs retained. |

`scripts/verify-cross-e2e-evidence.py` checks bundle consistency without target execution. `summary.json` links image/job/firmware IDs and report hashes. `runtime-provenance.json` records exact runtime image IDs and relevant source hashes.

## Controlled fixture construction

Only existing project-owned artifacts registered in `analysis-controlled.json` and `emulation-controlled.json` are accepted. The builder packages cross-architecture symbolic fixtures, benign service probes, fake scanner credentials/certificates and a proprietary-string sentinel into deterministic SquashFS images. Each new image is built twice and must match before its exact hash is registered. Four controlled image hashes were added; the original x86 entry was preserved. The analyzer and execution-gate logic were not changed.

Run `scripts/build-cross-pipeline-fixtures.py` inside `firmwarex-emulation-fixtures:task3`, UID 1000, network none, capabilities dropped, with these mounts: `work/fixtures:/fixtures`, `fixtures/manifests:/manifests`, `fixtures/sources:/sources:ro`, `scripts:/scripts:ro`, `evidence/cross-e2e:/evidence`. The recorded binary inputs originate from `build-analysis-fixtures.sh` and `build-emulation-fixtures.sh`; their existing controlled registries are checked before packaging. A rebuilt artifact with a different hash is rejected rather than silently authorized.

Build the production pipeline image, start the existing Compose services and wait for API readiness. Run `verify-cross-e2e.py`. Run `verify-cross-e2e-storage.py` through the trusted dispatcher with scripts/evidence mounts. Run `verify-cross-e2e-reports.cjs` using the configured Node/Playwright runtime. Never execute the fixture binaries directly on the host. The older offline component-report exporter is not used for these reports.

## Limits and approval gates

**Real/vendor firmware dynamic execution remains PENDING HUMAN REVIEW under FWX-SAFE-009.** The unregistered-image regression still denies both emulation and symbolic execution. No mentor approval is inferred.

These small controlled user-space images do not demonstrate full vendor Linux boot. QEMU executes the benign service binary; the separate taint fixture is symbolically analyzed without running shell commands. No native crash is required or claimed for the non-x86 CWE-78 diagnostics. The quota fault tests are controlled host workloads under the same production container profile, not a separate guest-ISA quota suite. Controlled-fixture timings do not satisfy a representative real-image performance KPI.

This closes the controlled cross-architecture E2E evidence gap. Full PRD acceptance remains **78 PASS / 34 FAIL**: evidence scope is strengthened, but real-image/human-review obligations are not promoted to PASS. Relevant IDs: FWX-FUNC-001, STATIC-003, EMU-001/002/004, SYM-001/002, SAFE-003/004/006, API-005/006, OBS-002, DELIV-004, DOD-006/008.

Resolved setup issues: the initial build could not overwrite a root-owned historical manifest, corrected using atomic replacement; the local API was initially stopped, then started before successful uploads; the offline evidence writer needed the evidence-directory owner UID. Successful checks were rerun. No architecture-specific analyzer failure occurred. No optional features, external publication or real-firmware execution occurred.
