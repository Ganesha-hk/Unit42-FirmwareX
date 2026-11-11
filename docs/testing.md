# Validation and evidence guide

Latest follow-up: [2026-11-07 hardening validation](hardening-validation.md). Browser scripts now resolve Playwright through `FWX_PLAYWRIGHT_MODULE` or normal Node module resolution; the earlier machine-specific import paths have been removed. Use the actual host UID/GID for writable evidence mounts. New regressions: `tests/unit/test_hardening_regressions.py`, `scripts/verify-source-models.py`, `scripts/verify-concurrent-uploads.py` and `scripts/verify-output-quota.py`. Source-model checks run with the analysis image and `/fixtures` mounted; output probes use the trusted dispatcher and production sandbox. Neither executes unregistered firmware.

Run tests from the repository root with the local stack available. Never treat a test's presence as evidence it passed. Save logs, machine-readable results, revision and actual exit status. Test records are fixtures; do not delete production records as test cleanup.

## Unit and whole-package coverage

```sh
mkdir -p evidence/task6
docker run --rm --user 1000:1000 --network none --cap-drop ALL --memory 768m \
  -e COVERAGE_FILE=/tmp/.coverage -v "$PWD/src:/app/src:ro" \
  -v "$PWD/tests:/tests:ro" -v "$PWD/work/fixtures:/fixtures:ro" \
  -v "$PWD/evidence/task6:/evidence" firmwarex-control:day1 \
  pytest -p no:cacheprovider /tests/unit --cov=firmwarex \
  --cov-report=xml:/evidence/coverage.xml --cov-report=term \
  --junitxml=/evidence/unit-tests.xml
```

UID must match the evidence directory owner. Whole-package unit coverage includes unexecuted integration-only modules and therefore is lower than prior scanner/schema scoped coverage. External sandbox integration is not included in the unit coverage percentage. PRD does not specify a coverage threshold; uncovered lines remain visible.

## Real integrations

- `scripts/verify-pipeline.py`: controlled upload, gate, findings, trace, seven routes.
- `scripts/verify-final-corpus.py`: all six frozen public-image hashes and current extraction/inventory/matrix/report results. It does not execute untrusted binaries or claim a symbolic-performance pass.
- `scripts/verify-quotas.py` in the dispatcher with FWX_TEST_SCOPE=pipeline: independent CPU, memory, wall and network/host restrictions plus cleanup.
- `scripts/verify-task5-storage.py`: protected output, persisted evidence and append-only audit sentinel checks.
- `scripts/verify-analysis.py`, `verify-analysis-guards.py`, `verify-redaction.py`, `verify-emulation.py`: separately registered controlled analysis and emulation suites, mounted fixtures/registries; see Task 3/4 reviews.
- Browser scripts verify the UI, friendly names and readable reports. They need Playwright and Chromium installed; production UI does not. Existing scripts reference this environment's bundled runtime, an explicitly recorded portability limitation.

Earlier API/static scripts expected static_complete; use the integrated verifier for current code. Do not reinterpret an execution-blocked partial result as a complete real-image assessment. Benchmark static plus symbolic only after approval, recording image, target selection, hardware, budgets and elapsed stages. Record the entire corpus denominator, including failures.

## Review gates

See docs/final-validation.md for PASS/FAIL per requirement. Mentor isolation/quota approval, sensitive-code PR review, public-image dynamic evidence and an independent new-engineer reproduction cannot be self-certified by automated tests. Do not push or publish without user approval.

## Completion regression (2026-10-20)

Current results are in `evidence/completion/summary.json`; use `evidence/completion` in the unit/coverage command above to preserve Task 6 history. The final run passed 85 tests. The existing component suites were reused where their implementation was unchanged; they were not all rerun.

```sh
FWX_EVIDENCE_DIR=evidence/completion python3 scripts/verify-pipeline.py
FWX_EVIDENCE_DIR=evidence/completion python3 scripts/verify-task5-api-guards.py
docker compose run --rm --no-deps -v "$PWD/scripts:/scripts:ro" dispatcher python /scripts/verify-lifecycle.py
docker compose run --rm --no-deps -v "$PWD/scripts:/scripts:ro" dispatcher python /scripts/verify-recovery-admission.py
docker compose run --rm --no-deps -v "$PWD/scripts:/scripts:ro" dispatcher python /scripts/verify-database.py
docker compose run --rm --no-deps -v "$PWD/scripts:/scripts:ro" -v "$PWD/evidence/completion:/evidence" dispatcher python /scripts/verify-task5-storage.py
```

The dashboard and readable-report browser scripts also accept `FWX_EVIDENCE_DIR=evidence/completion`. Use the configured Node/Playwright runtime. They exercise authentication, graph edges/selection, 11 trace rows, filtered findings, responsive layout and JSON/HTML/PDF output.

Historical maintenance is explicit and privileged. `verify-output-boundary.py` creates synthetic legacy metadata, checks four API surfaces, then invokes `redact-historical-output.py`. Run via the **migrate** service with the scripts directory mounted; wait for active jobs to finish first. The migration URL is supplied by Compose, never print it. This operation changes normal historical metadata/output, saves restricted originals and leaves immutable evidence/audit history intact. The current successful result is recorded in `evidence/completion/output-boundary.log`; do not rerun merely to regenerate unchanged evidence.

## Controlled cross-architecture E2E

See docs/cross-architecture-e2e.md for fixture packaging, exact-hash authorization, runtime provenance and commands. New scripts: build-cross-pipeline-fixtures.py, verify-cross-e2e.py, verify-cross-e2e-storage.py, verify-cross-e2e-reports.cjs, verify-cross-e2e-evidence.py. The last script checks recorded evidence only and runs network-disabled in the control image as the evidence-directory owner. All target execution stays in production job sandboxes. PDF checks render every page; normal API/report data remains redacted. Do not reclassify partial/blocked jobs as complete.
