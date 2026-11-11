# FirmwareX — permitted Task 5 completion report

Superseding ledger update — 2026-11-08: **95 PASS / 17 FAIL** across 112 records; 150 unit tests pass. This remains NOT ACCEPTED.

Historical report: the current 2026-11-07 state is documented in [release readiness](release-readiness.md), [hardening validation](hardening-validation.md), and [final validation](final-validation.md). Current ledger: **87 PASS / 25 FAIL**. Mentor-authorized sampling and controlled optional stages now exist; statements below about absent authorization/deferred implementation apply only to the earlier milestone.

Latest cross-architecture follow-up: [controlled E2E validation](cross-architecture-e2e.md) now verifies the full production pipeline and actual dashboard reports on x86_64, ARM32, ARM64, MIPS and MIPSEL. Earlier component-only exports are historical. Full PRD acceptance remains 78 PASS / 34 FAIL; real/vendor execution remains PENDING HUMAN REVIEW.

Date: 2026-10-20. **The remaining permitted Task 5 core integration work passes. The complete PRD release is NOT ACCEPTED.** The requirement ledger contains **78 PASS / 34 FAIL across all 112 IDs**. FAIL includes unmet, deferred and human-gated obligations; it does not mean 34 regression tests failed.

## Work completed

- Linked upload, queue wait, sandbox execution, six analysis stages, pipeline parent and persistence into one OpenTelemetry trace: 11 spans with SDK lifecycle metrics. Launcher exceptions, quota errors, invalid persistence results and abandoned-job recovery retain content-free diagnostics. A killed process cannot export its unfinished internal spans; controller failure telemetry remains available.
- Added a shared, idempotent output filter for current pipeline serialization, controller persistence and historical API reads. Reviewed structural metadata remains usable; unreviewed text and keys become salted fingerprints. Preserved graph edge addresses, normalized findings and evidence references.
- Sanitized 22,208 historical metadata records and 47 historical output files. Originals are quarantined under the controller-only private storage directory, outside normal API/export access. Immutable finding evidence was validated without rewriting it. Immutable audit history remains unchanged; maintenance appends an audit event. User-entered labels and restricted raw inputs are separate from firmware-derived diagnostics.
- Added output-artifact digests/references to completion audit events and verified runtime denial of audit UPDATE, DELETE and TRUNCATE.
- Updated the dashboard telemetry view and preserved the readable assessment report, downloadable HTML and printable PDF.

Newly closed requirement rows: **FWX-FUNC-001, FWX-DELIV-004, FWX-OBS-001, FWX-OBS-002, FWX-SAFE-006, FWX-DOD-006, FWX-DOD-008**. Evidence is scoped to the controlled tests and documented output contract; the universal redaction/containment KPIs remain unverified.

## Final validation

| Check | Actual result | Evidence |
| --- | --- | --- |
| Current unit regression | 85 passed; zero failures/errors | `evidence/completion/unit-tests.xml` |
| Whole-package unit coverage | 32.81%; external sandbox integration excluded | `evidence/completion/coverage.xml` |
| Real queued pipeline | 2 passed: controlled image complete with 17 findings; unregistered fixture partial with execution denied | `evidence/completion/pipeline-results.json` |
| Trace propagation | 11 spans, one trace, analysis parent points to controller sandbox span | `evidence/completion/controlled-report.json` |
| Infrastructure failure injection | 3 passed: launcher exception, quota result, invalid persistence result; real database, mocked launcher | `evidence/completion/lifecycle-failures.json` |
| Recovery/admission | 16-job limit rejects with 429; health stays available; stale-job container removed and recovery traced | `evidence/completion/recovery.json` |
| Historical output boundary | 4 API surfaces redact an adversarial legacy fixture before maintenance; metadata/output cleanup passes | `evidence/completion/output-boundary.log` |
| Storage and audit | Sentinel absence, lifecycle events and output hashes pass; mutation attempts denied | `evidence/completion/storage-results.json`, `audit-integrity.json` |
| API authorization | 8 report/finding guard cases pass | `evidence/completion/api-guards.json` |
| Dashboard | 10 interaction groups pass; no browser errors | `evidence/completion/browser-results.json` |
| Readable report | 8 check groups pass, including escaping, 17 findings, HTML/PDF, token/sentinel absence, blocked-stage disclosure | `evidence/completion/results.json`, `sample-report.pdf` |

The new PDF first page was rendered and visually inspected. Prior unchanged component evidence is reused, not presented as newly rerun: 42 symbolic cases, 36 emulation cases across five architectures, four pipeline quota/containment cases and 6/6 frozen public-image static/scanner analyses (`evidence/task6/`). Static corpus timings do not establish a symbolic performance KPI.

Development failures were resolved before the passing checks: asynchronous API startup, an accidental database-only import inside the analysis image, and a historical maintenance attempt rejected by immutable-evidence permissions. See `evidence/completion/development-notes.json`. No claim is made that development was error-free.

## Deferred work and human gates

**Real firmware execution: PENDING HUMAN REVIEW.** No mentor approval, approved revision or scope has been supplied. The exact controlled-image gate remains enabled. No real firmware binaries were executed in this completion pass.

**No operation in this pass was blocked by cybersecurity safety policy.** Therefore none is falsely labeled BLOCKED BY SAFETY POLICY. The optional crash-testing prototype had stopped at a SyntaxError before execution; it was not retried. Its unfinished source and build logs are set aside under ignored `work/deferred-fuzz/`, outside product code. FWX-FUZZ-001–003 remain FAIL/DEFERRED (Should), per the instruction not to start optional work. Snapshot/restore remains deferred (Could); full vendor-system bring-up remains partial (Should). These requirements are retained, not waived.

Final acceptance still requires the items in `docs/final-validation.md`, notably mentor containment/quota approval, representative real-image dynamic/taint/throughput evidence and demo, corpus agreement, confidence/CWE calibration review, independent clean-machine reproduction, milestone reviews and the PR workflow/sensitive-code review. Broad all-producer normalization and universal KPI evidence remain unclosed. See `docs/security-review.md` for the review packet. Blocked, deferred and unverified requirements are never counted PASS.

No GitHub push, PR publication, merge, visibility change or external communication occurred. Local commits record the milestone; external publication still needs user approval.

## Reproduction and maintenance notes

Use isolated Python 3.12 images and the existing hash-locked dependencies. System Python remains unchanged. QEMU software emulation remains the supported path without `/dev/kvm`.

`docs/testing.md` lists final regression commands. `scripts/redact-historical-output.py` is an explicit privileged maintenance operation, not a web endpoint. Run only with no active jobs, through the migration service supplying `FWX_MIGRATION_URL`; it quarantines originals with restricted permissions and does not rewrite audit/finding evidence. Keep quarantine private. It is not included in the delivery archive.

The canonical current state is `REQUIREMENTS.md`, `docs/requirements-traceability.md`, `docs/final-validation.md` and `evidence/completion/summary.json`. Earlier milestone counts remain historical evidence.
