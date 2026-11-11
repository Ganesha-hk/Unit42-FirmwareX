# Release readiness — NOT ACCEPTED

Current submission — 2026-11-10: **159 unit tests passed; selected OpenWrt checks complete.** Static plus selected analysis: **4.209340868 seconds**. Requirement ledger: **105 PASS / 7 FAIL**. Real-image crash validation and independent clean-machine reproduction remain open. See `docs/submission-2026-11-10.md` for evidence and reproduction.

## Historical assessment

Earlier milestone counts and partial-status statements below are retained as history; use the current submission record and ledger.

Updated 2026-11-07. This document supersedes older operational statements that all unregistered execution is blocked or that optional work remains deferred at the user's request. It does not silently replace requirement results: the full ledger is docs/final-validation.md.

## Working and evidenced

- Authenticated upload, extraction, filesystem inventory, ELF audit, secret/crypto scanning, queue/persistence, dashboard and exports.
- Controlled QEMU and symbolic pipelines across five architectures; earlier results remain dated evidence.
- Current scanner accuracy fixes and 128 passing unit tests. See hardening-validation.md.
- Mentor-authorized real-image startup and bounded symbolic sampling. The original demo assessment is preserved; reanalysis creates a separate assessment.
- Real OpenWrt 24.10.4 uhttpd serves a synthetic page over isolated loopback. Browser upload-to-report recording verifies 1,571 entries, 171 ELF binaries and 20 candidate findings. Evidence: `evidence/mentor-accuracy-2026-11-07/openwrt-demo/`. Whole-image emulation/symbolic status remains partial.
- Controlled HTTP/UPnP/MQTT fuzzing, seeded input minimization, verified diagnostic replay and stack-based deduplication: `evidence/mentor-accuracy-2026-11-07/fuzz-result.json`.
- Controlled ARM snapshot/restore, two state restorations with cleanup verification: `evidence/mentor-accuracy-2026-11-07/snapshots.json`.

These optional features apply to registered fixtures. They do not establish arbitrary vendor protocol fuzzing or vendor full-system snapshots.

## Remaining acceptance obligations

1. Real-image taint-to-sink/crash evidence with defensible CWE and confidence. A help invocation or an early symbolic startup path is insufficient.
2. Precision/recall and human classification review on a declared sample. Fewer scanner alerts do not prove accuracy.
3. Representative static-plus-symbolic performance acceptance with declared coverage and hardware. Incomplete work below the time limit is not a passing benchmark.
4. Final containment/redaction coverage audit over all relevant execution/output paths and the declared test denominator. Passing probes do not prove absence of every possible escape or leak.
5. License/provenance review of selected release inputs and third-party dependencies.
6. Independent clean-environment runbook reproduction and sensitive-code PR review.
7. Required milestone review/pairing records. Automation cannot invent past meetings or independent reviewer approval.

The user has authorized local implementation and mentor-controlled testing. This does not constitute independent review, authorization to publish proprietary inputs, or permission to push/merge changes externally.

## Local operation

Run `docker compose up -d` using the private `.env`. Open `http://127.0.0.1:8000/`, authenticate, and select an assessment. **Run again** preserves the original and creates a new assessment. Existing reports retain their historical stage results. `FWX_MENTOR_AUTHORIZED_EXECUTION=false` restores the unregistered-image execution gate for new jobs.

Tests: `scripts/verify-demo-reanalysis.py`, `scripts/verify-extended-pipeline.py`, `scripts/verify-final-corpus.py` (set `FWX_EVIDENCE_DIR` for a new output directory), and the unit/browser suites documented in testing.md. The fuzz and snapshot verification scripts run in the existing trusted dispatcher with read-only fixtures and launch their workloads in a separate production sandbox.
