# FirmwareX Acceptance Contract

Current submission — 2026-11-10: **159 unit tests passed; selected OpenWrt checks complete.** Static plus selected analysis: **4.209340868 seconds**. Requirement ledger: **105 PASS / 7 FAIL**. Real-image crash validation and independent clean-machine reproduction remain open. See `docs/submission-2026-11-10.md` for evidence and reproduction.

## Historical assessment

Earlier milestone counts and partial-status statements below are retained as history; use the current submission record and ledger.

## Current status — 2026-11-07

Superseding ledger update — 2026-11-09: **102 PASS / 10 FAIL across 112 requirement records**; 150 unit tests pass. The detailed current ledger is `docs/final-validation.md`.

**NOT ACCEPTED: 87 PASS / 25 FAIL across 112 requirement records.** The updated rows are in docs/final-validation.md; evidence is in evidence/mentor-accuracy-2026-11-07/validation-counts.json. There are 128 passing unit tests. All six frozen OpenWrt images pass the declared extraction/static success rule. Controlled fuzzing/replay/deduplication and snapshot restoration now pass both dedicated tests and complete queued pipeline tests.

The user has supplied mentor authorization for local execution; the deployment supports bounded real-image sampling. This supersedes old statements below about absent authorization and optional work being deferred. Independent review, full real-image dynamic/taint evidence, calibration, benchmark acceptance and reproduction are not established. Older dated sections are historical records, not the current state.

FirmwareX is accepted only when the PRD Definition of Done is demonstrated.

## Required acceptance conditions

- [ ] End-to-end pipeline works from firmware upload to CWE-classified report.
- [ ] Results are viewable through the dashboard.
- [ ] Extraction succeeds on >90% of the defined standard open-source test set.
- [ ] Binary execution/emulation occurs only inside the sandbox.
- [ ] Workers have proven zero external network egress.
- [ ] CPU quotas are enforced.
- [ ] Memory quotas are enforced.
- [ ] Wall-clock limits are enforced.
- [ ] A quota-breaching job is demonstrably terminated.
- [ ] Findings conform to the normalized finding schema.
- [ ] Findings contain CWE classification.
- [ ] Findings contain confidence.
- [ ] Raw discovered secrets are not persisted by default.
- [ ] Secret fingerprint/redaction behavior is demonstrated.
- [ ] Static audit + basic symbolic trace meets the PRD performance target on
      the representative test image.
- [ ] Required REST API functionality exists.
- [ ] Required dashboard views exist.
- [ ] OpenTelemetry traces job lifecycle stages.
- [ ] Core modules have automated tests.
- [ ] Coverage report exists.
- [ ] README/setup/runbook reproduce a complete run.
- [ ] Architecture documentation matches delivered implementation.
- [ ] Required evidence package exists.

## Evidence required

Evidence must come from actual execution, not manually fabricated examples.

Required evidence includes:

- repository/commit history;
- architecture diagram;
- named permitted firmware extraction output;
- filesystem inventory;
- mitigation matrix;
- checksec comparison;
- QEMU execution evidence;
- no-egress proof;
- quota termination proof;
- symbolic/taint finding;
- diagnostic crash state;
- normalized CWE JSON;
- redacted secret finding;
- proof plaintext secret was not persisted;
- API examples;
- end-to-end run;
- throughput measurement;
- test coverage report.

## Final validation

Generate docs/final-validation.md.

For every PRD requirement record:

Requirement
Implementation
Test
Evidence
PASS/FAIL
Notes

Unknown or untested means FAIL/UNVERIFIED, never PASS.

## Extracted PRD acceptance supplement — 2026-10-19

REQUIREMENTS.md contains the exact canonical obligations and priority basis. docs/requirements-gap-analysis.md identifies original omissions. docs/requirements-traceability.md maps each to implementation, test and evidence. Every Must below blocks completion until real verification succeeds; Should and Could remain visible with their actual result/deferred status.

- [ ] Prove all six filesystem families, nested compression/custom headers and entropy support; inventory exact metadata and shared-library ELFs.
- [ ] Test all required architecture/endianness paths, including MIPSEL representation; prove TCG path without KVM.
- [ ] Prove contained HTTP/UPnP/MQTT networking; no packets escape.
- [ ] Verify host/syscall restrictions, aggregate back-pressure and all independent quota breaches.
- [ ] Enforce mentor approval before untrusted emulation; record reviewer and sandbox revision.
- [ ] Verify source models, all named sinks, reaching conditions, complete diagnostic crash fields, state/depth/time/memory/path budgets, pruning/merging and incomplete reporting.
- [ ] Validate every Appendix A field/type/nullability/enum; version schema; spot-check confidence and CWE applicability.
- [ ] Prove append-only audit of inputs/parameters/artifacts/findings and OpenTelemetry stage traces plus metrics.
- [ ] Prove redaction for stored/displayed/logged/traced/exported output including proprietary strings; gated/audited reveal and salted fingerprint-only normal results.
- [ ] Validate exact seven routes and four UI behaviors, including risk sorting, interactive selected-function CFG and finding filters.
- [ ] Measure extraction >90% on frozen standard corpus and static audit plus basic symbolic trace <1800 seconds on representative image; record hardware/config/denominators.
- [ ] Submit real-image findings, screen recording, named-image outputs and reproducibility evidence; synthetic fixture findings do not replace real-image evidence.
- [ ] Complete PR reviews (extra scrutiny for sandbox/quota/redaction), daily progress, incremental demos and mentor pairing.
- [ ] Verify README/runbook deployment/submission/results/teardown with a new engineer; architecture and final trade-offs match actual code.
- [ ] Record Should results: banned-function/W+X leads; best-effort full-system stubs/fallback; all three protocol fuzzers; seeded/minimized replay; stack dedup.
- [ ] Record Could snapshot/restore result or explicit deferral; do not mislabel it Must.

### Complete acceptance ID register

The detailed test and evidence for each ID are in the canonical index; a checked category requires every listed Must to be verified, with Should/Could dispositions separately recorded. This register prevents a broad feature check from silently omitting subrequirements.

- [ ] SCOPE: FWX-SCOPE-001, FWX-SCOPE-002, FWX-SCOPE-003, FWX-SCOPE-004, FWX-SCOPE-005.
- [ ] FUNC: FWX-FUNC-001.
- [ ] ARCH: FWX-ARCH-001, FWX-ARCH-002, FWX-ARCH-003, FWX-ARCH-004.
- [ ] STATIC: FWX-STATIC-001, FWX-STATIC-002, FWX-STATIC-003, FWX-STATIC-004, FWX-STATIC-005, FWX-STATIC-006.
- [ ] EMU: FWX-EMU-001, FWX-EMU-002, FWX-EMU-003, FWX-EMU-004, FWX-EMU-005.
- [ ] SYM: FWX-SYM-001, FWX-SYM-002, FWX-SYM-003, FWX-SYM-004.
- [ ] FUZZ: FWX-FUZZ-001, FWX-FUZZ-002, FWX-FUZZ-003.
- [ ] SECRET: FWX-SECRET-001, FWX-SECRET-002.
- [ ] SAFE: FWX-SAFE-001, FWX-SAFE-002, FWX-SAFE-003, FWX-SAFE-004, FWX-SAFE-005, FWX-SAFE-006, FWX-SAFE-007, FWX-SAFE-008, FWX-SAFE-009.
- [ ] OBS: FWX-OBS-001, FWX-OBS-002.
- [ ] API: FWX-API-001, FWX-API-002, FWX-API-003, FWX-API-004, FWX-API-005, FWX-API-006, FWX-API-007.
- [ ] UI: FWX-UI-001, FWX-UI-002, FWX-UI-003, FWX-UI-004.
- [ ] SCHEMA: FWX-SCHEMA-001, FWX-SCHEMA-002, FWX-SCHEMA-003, FWX-SCHEMA-004, FWX-SCHEMA-005, FWX-SCHEMA-006, FWX-SCHEMA-007, FWX-SCHEMA-008, FWX-SCHEMA-009, FWX-SCHEMA-010, FWX-SCHEMA-011, FWX-SCHEMA-012, FWX-SCHEMA-013, FWX-SCHEMA-014, FWX-SCHEMA-015, FWX-SCHEMA-016, FWX-SCHEMA-017, FWX-SCHEMA-018, FWX-SCHEMA-019, FWX-SCHEMA-020, FWX-SCHEMA-021, FWX-SCHEMA-022, FWX-SCHEMA-023.
- [ ] DELIV: FWX-DELIV-001, FWX-DELIV-002, FWX-DELIV-003, FWX-DELIV-004, FWX-DELIV-005, FWX-DELIV-006, FWX-DELIV-007, FWX-DELIV-008, FWX-DELIV-009.
- [ ] TEST: FWX-TEST-001.
- [ ] EVID: FWX-EVID-001, FWX-EVID-002, FWX-EVID-003, FWX-EVID-004, FWX-EVID-005, FWX-EVID-006, FWX-EVID-007, FWX-EVID-008, FWX-EVID-009.
- [ ] KPI: FWX-KPI-001, FWX-KPI-002, FWX-KPI-003, FWX-KPI-004, FWX-KPI-005.
- [ ] DOD: FWX-DOD-001, FWX-DOD-002, FWX-DOD-003, FWX-DOD-004, FWX-DOD-005, FWX-DOD-006, FWX-DOD-007, FWX-DOD-008, FWX-DOD-009.
- [ ] GOV: FWX-GOV-001, FWX-GOV-002, FWX-GOV-003, FWX-GOV-004.

No requirement is accepted in this planning milestone. At final validation, use PASS/FAIL per AGENTS.md; missing or untested evidence remains FAIL with an UNVERIFIED note. No numerical coverage threshold is prescribed by PRD; report measured coverage honestly. Never lower any PRD Must because the five-day schedule expires.

## Current acceptance outcome — 2026-10-20

The remaining permitted Task 5 core integration, lifecycle telemetry and output-boundary work passes the recorded checks in docs/completion-report.md. Current all-requirement ledger: **78 PASS / 34 FAIL** in docs/final-validation.md. There were **85 passing unit tests and zero unit failures/errors**; unmet requirements are not regression-test failures.

Final project acceptance is **NOT ACCEPTED**. Real firmware execution stays **PENDING HUMAN REVIEW**. Optional Should fuzz/replay/dedup remains deferred at user direction, not passed or waived. No actual safety-policy block occurred in this pass. Human review, representative-image dynamic/benchmark evidence, calibration, reproduction and remaining ledger obligations still apply. Earlier milestone outcomes are historical, not unconditional final approval.

## Controlled cross-architecture E2E follow-up

2026-10-20: all five controlled firmware images pass the full upload-to-dashboard pipeline. Reports are generated by the actual application. Evidence: docs/cross-architecture-e2e.md and evidence/cross-e2e/summary.json. Fresh regression: 85 unit tests, two pipeline cases including denied unregistered execution, eight API guards, dashboard checks and four shared-profile quota/network cases pass. This closes the controlled E2E coverage gap; it does not authorize real/vendor execution or change the 78 PASS / 34 FAIL final acceptance count.
