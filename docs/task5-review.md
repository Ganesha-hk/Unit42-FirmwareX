# Task 5 — integrated pipeline and dashboard

The Day 4 controlled-image gate passes: one uploaded, exactly registered image traverses extraction, ELF audit, contained QEMU execution and HTTP/UPnP/MQTT probes, bounded angr analysis, secret/crypto scanning, normalization, PostgreSQL persistence, authenticated reports and the dashboard. This is a scoped engineering milestone, not final PRD acceptance.

## Verified results

- 78 unit/regression tests passed (`evidence/task5/unit-tests.xml`).
- Real queued HTTP integration: registered image complete, 17 findings, two audited ELF binaries, six inventory entries; unregistered image partial with both execution stages blocked. All seven required API routes exercised (`pipeline-results.json`, `controlled-report.json`, `gated-report.json`).
- Browser checks passed: login, overview, file metadata, risk sorting, CWE filtering, evidence inspection, real CFG selection/zoom, telemetry, redacted report download and mobile layout. No page JavaScript errors. Seven screenshots retained; desktop/mobile overview visually reviewed (`browser-results.json`).
- Eight new report/finding route authentication, missing-ID and invalid-ID checks passed (`api-guards.json`).
- Real PostgreSQL, audit rows and sandbox result files contained none of five synthetic secret/proprietary sentinels; six stage audit events and finding persistence verified for both jobs (`storage-results.json`). This is measured fixture coverage, not a universal redaction guarantee.
- The pipeline sandbox profile passed four real wall/CPU/memory/network tests, including cleanup, non-root UID, host-connect denial, IPv4/IPv6 routing denial, mount denial and absence of Docker socket (`pipeline-quotas.json`). Task 3 packet-capture evidence remains separate; no new packet capture is claimed here.
- Seven OpenTelemetry SDK spans share a trace ID: root pipeline plus six analysis stages; duration histograms and completed-stage counters are persisted with the report. Failed-before-output jobs and control-plane queue/persistence spans remain an observability gap.

## Implementation and decisions

`pipeline.py` keeps raw extracted content inside one offline quota-bound sandbox. Exact image and target SHA-256 registry checks are required for controlled execution; a caller-supplied provenance label cannot authorize it. Arbitrary/untrusted execution remains blocked pending mentor approval.

Scratch remains noexec. Linux QEMU executable mappings require an executable filesystem, so the pipeline adds a 32 MiB, nodev/nosuid `/guest` tmpfs, populated only after target hash verification. Repeated execution revalidates the staged hash. The outer sandbox still has no network, capabilities or host socket, a read-only image, resource caps and forced cleanup. This change needs explicit sensitive-code review with the mentor; no self-approval is recorded.

Python remains isolated 3.12; angr and OpenTelemetry 1.45.1 dependencies are hash locked and installed together with `pip check`. No system-Python replacement. The UI uses local HTML/CSS/JavaScript and real angr CFG data; no browser build/runtime dependency is needed in production. This supersedes the proposed TypeScript/Vite/Cytoscape UI choice, which was a planning decision rather than a PRD requirement. OpenTelemetry exports locally to preserve zero worker egress.

Unreviewed path components become stable salted pseudonyms; metadata/hashes remain browsable. Secret values and raw file contents are not returned. Existing pre-Task-5 static records were not retroactively rewritten, so legacy metadata sanitization remains a final-validation item. Raw reveal stays disabled.

## Reproduction

See `docs/runbook.md` for build/start, submission, reports and shutdown. After fixture/image builds, run `python3 scripts/verify-pipeline.py`, `python3 scripts/verify-task5-api-guards.py` and `node scripts/verify-dashboard.cjs` (Playwright and Chromium required for the browser verifier). Run storage/quotas verifiers in the trusted dispatcher as documented in the runbook. Production UI does not require Node.

Failed development attempts were corrected: executable mappings from noexec scratch; reuse of read-only staged binaries; browser graph clicks intercepted by pan pointer capture. Startup-race failures and earlier attempts remain in evidence; only the final successful checks above establish results.

## Requirements and remaining acceptance work

Scoped evidence covers FWX-FUNC-001, FWX-API-005/006, FWX-UI-001–004, FWX-DELIV-004/007 and controlled parts of FWX-OBS-001/002, FWX-SAFE-001–007 and FWX-SCHEMA-021. Traceability retains narrower status where the full requirement is not met.

Explicitly still open: FWX-FUZZ-001–003 (Should: protocol fuzzing, minimized/replayable crash corpus and stack dedup); complete lifecycle/failure tracing (FWX-OBS-002); universal/historical output sanitization; vendor/real-image execution and final corpus/performance/coverage/demo/reproduction acceptance. Service probes are not fuzzing. These requirements were not removed or counted as passing.

Human gates: mentor containment/quota sign-off before arbitrary untrusted execution; sandbox/quota/redaction PR review; corpus/findings review and independent reproduction. GitHub publishing, pushing, PR creation or merging also require the user's prior approval. No external GitHub action was taken.

Static follow-up: the vulnerabilities endpoint now includes normalized low-risk heuristic banned-symbol leads, with CWE-676/CWE-242, explicit unproven invocation/overflow flags and no invented crash state. Two additional unit checks and a fresh end-to-end pipeline/browser/storage run verify the addition. See the primary-source mapping rationale in docs/decisions.md.

## Completion follow-up

The lifecycle and historical/output-boundary gaps described above were addressed on 2026-10-20. See **docs/completion-report.md** and **evidence/completion/summary.json** for 85 unit passes, 11 linked lifecycle spans, failure/recovery checks and metadata cleanup. Earlier numbers above are historical. The permitted core passes; optional Should fuzz work remains deferred and full PRD acceptance remains open (78 PASS / 34 FAIL).
