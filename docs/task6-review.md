# Task 6 validation review — release NOT accepted

The validation pass and evidence package are complete for the locally authorized scope. **Task 6/final PRD acceptance is not complete.** Required real-image execution is blocked by missing mentor containment/quota sign-off; other engineering and independent-review gaps remain. Do not describe the product as error-free or fully accepted.

## Verified results

- 78 unit tests passed; whole-package unit line coverage is 28.66%. External container integrations are not included in that coverage number.
- 42 real sandboxed symbolic-analysis cases passed: modeled source/sink matrix, negative examples, memory regions/fault diagnostics, architecture cases and explicit budget stops.
- 36 QEMU cases passed across five architectures, including service probes, guest containment, quota breaches, controlled boot and fallback behavior.
- Four independent pipeline-profile wall/CPU/memory/network/cleanup regressions passed. Nine prelaunch/raw-reveal guard cases passed.
- Six of six SHA-256-verified frozen OpenWrt 24.10.4 images unpacked. Their matrices contain 171, 171, 186, 209, 153 and 153 binaries; 1,941 persisted real-image static/scanner candidate findings passed schema validation. Candidate count is not a count of confirmed vulnerabilities.
- Real-image upload-to-partial-report elapsed times were 4.238–5.254 seconds on this host. **These are not static-plus-symbolic benchmark results**: execution stages were blocked as required.
- Controlled upload-to-report still passes with 17 findings. The unregistered controlled image remains partial with execution blocked. Persisted-output sentinel checks passed; repeated scanner runs retained eight deduplicated findings with zero synthetic plaintext matches.
- Migration upgrade/downgrade/re-upgrade passed in a disposable database. Fault injection at the persistence boundary verified atomic rollback, generic failure output and durable failure audit.
- Readable-report browser checks passed. A video records controlled upload through report review. It does not substitute for the gated real-image dynamic demonstration.

Machine-readable sources: evidence/task6/summary.json, validation-counts.json, corpus-results.json, symbolic-results.json, integration.json, quotas.json, analysis-guards.json, persistence-failure.json and coverage.xml. Failed initial runs are described below rather than counted as passing evidence.

## Bugs found and fixed

1. The integrated runner's 32 MiB RLIMIT_FSIZE also capped decompression, so larger valid gzip root filesystems failed. Extraction now uses its existing 512 MiB bound, while serialized reports separately enforce 32 MiB and the launcher independently checks that output limit. All six actual corpus images passed after correction; compressed/decompressed input hashes were checked rather than assuming fixtures were valid.
2. Persistence exceptions previously escaped after a job entered running state. The worker now rolls back the result transaction and writes a generic failed status/audit without persisting invalid result text. The injected malformed-result test verifies the failure path against real PostgreSQL.
3. The initial coverage run used a container UID unable to write the mounted evidence directory. The rerun used the directory owner's UID and a writable coverage temporary path; final JUnit and coverage output were actually created.

## Final ledger

`docs/final-validation.md` contains all 112 canonical requirements with PASS or FAIL, implementation/test/evidence links and scope notes. Current result: **71 PASS, 41 FAIL**. FAIL includes incomplete, blocked, deferred and unverified obligations; it does not mean 42 automated tests failed. PASS applies to the specific scope stated in the row and does not override any failing broader Must requirement.

Main open items:

- Mentor containment/quota sign-off before untrusted execution, then a reviewed real-image target-selection policy. Do not simply add public image hashes to the controlled registry.
- Actual real-image taint/crash evidence, static-plus-basic-symbolic throughput benchmark and complete real-image recorded demonstration.
- Complete lifecycle/failure OpenTelemetry, universal/historical output-redaction validation, calibrated real-image findings review and independent new-engineer reproduction.
- Protocol fuzzing, deterministic minimized crash replay and stack dedup (Should); snapshot/restore (Could) remains deferred. Service probes are not fuzzing.
- Agreed standard corpus/reviewer acceptance; incremental demo/mentor pairing and sensitive-code PR review. GitHub actions need separate user authorization.

## Review handoff

Architecture and boundary diagram: docs/architecture.md. Reproduction: docs/runbook.md and docs/testing.md. Reviewable safety packet: docs/security-review.md. Decisions/limitations: docs/decisions.md and docs/known-limitations.md. Findings and reports are diagnostic and redacted; raw source images, private salts and credentials are excluded from delivery.

No arbitrary firmware was executed. No approval, review, push, PR creation or publication was invented or performed. Human approval remains a real release blocker even though the controlled engineering checks pass.
