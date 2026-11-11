# FirmwareX Implementation Tasks

Current submission — 2026-11-10: **159 unit tests passed; selected OpenWrt checks complete.** Static plus selected analysis: **4.209340868 seconds**. Requirement ledger: **105 PASS / 7 FAIL**. Real-image crash validation and independent clean-machine reproduction remain open. See `docs/submission-2026-11-10.md` for evidence and reproduction.

## Historical assessment

Earlier milestone counts and partial-status statements below are retained as history; use the current submission record and ledger.

## Current follow-up — 2026-11-07

- [x] Repair concurrency, output bounds, source semantics and stage failure handling.
- [x] Add mentor-authorized real-image sampling and preserve original assessments on reanalysis.
- [x] Reduce unsupported entropy/certificate findings; verify NUL-delimited scanner context.
- [x] Verify controlled HTTP/UPnP/MQTT fuzzing, replay and stack dedup through the full pipeline.
- [x] Verify controlled ARM snapshot/restore twice, including full pipeline persistence.
- [x] Revalidate the frozen OpenWrt corpus: 6/6 extraction/static success.
- [x] Publish current hardening validation and release-readiness documents.
- [x] Verify real OpenWrt HTTP serving and record browser upload-to-report evidence.
- [ ] Complete remaining 25 acceptance rows; see docs/final-validation.md.

Current unit evidence: 128 passed; whole-package unit coverage 35.94%, excluding external integration execution. Historical checkboxes below describe dated milestones. Mentor authorization has been supplied; independent review and full acceptance are still outstanding.

## Day 1 — Foundation + Static Pipeline

- [x] Read and extract entire PRD
- [x] Complete requirements traceability
- [x] Inspect development environment
- [x] Establish repository structure
- [x] Docker Compose development environment
- [x] FastAPI skeleton
- [x] PostgreSQL models/migrations
- [x] Redis
- [x] Celery/RQ worker
- [x] Firmware upload + SHA-256 identification
- [x] Job lifecycle/status
- [x] Firmware storage
- [x] Binwalk extraction
- [x] Common filesystem handling
- [x] Rootfs reconstruction
- [x] File-tree inventory
- [x] ELF enumeration
- [x] Architecture detection
- [x] Endianness detection
- [x] Bitness detection
- [x] NX
- [x] PIE
- [x] RELRO
- [x] stack canary
- [x] FORTIFY
- [x] stripped status where applicable
- [x] mitigation matrix persistence
- [x] validate hardening results against checksec
- [x] extraction/static API endpoints
- [ ] tests
- [ ] evidence

DAY 1 GATE:
Firmware upload → extraction → filesystem → ELF → mitigation matrix works.

## Day 2 — Containment + QEMU

- [x] Sandbox design
- [x] Egress-denied worker execution
- [x] least privilege
- [x] CPU quota
- [x] memory quota
- [x] wall-clock quota
- [x] forced termination test
- [x] no-egress test
- [x] cleanup
- [x] QEMU user-mode abstraction
- [x] MIPS
- [x] MIPSEL
- [x] ARM32
- [x] ARM64
- [x] x86_64
- [x] reproducible controlled-fixture emulation
- [x] contained service networking where applicable
- [x] best-effort full-system support/fallback architecture
- [x] containment evidence

HUMAN GATE:
Do not execute arbitrary untrusted firmware until containment review/sign-off.

DAY 2 GATE:
Controlled binaries execute through QEMU inside quota-bound, no-egress sandbox.

## Day 3 — Symbolic/Taint + Secret/Crypto

- [x] angr integration
- [x] source modeling
- [x] sink modeling
- [x] strcpy/memcpy/sprintf sinks
- [x] system/popen command sinks
- [x] taint source-to-sink tracking
- [x] reaching/path condition
- [x] time budget
- [x] state/path budget
- [x] memory budget
- [x] pruning
- [x] partial/incomplete analysis result
- [x] diagnostic crash-state representation
- [x] candidate CWE mapping
- [x] secret pattern detection
- [x] private-key/certificate detection
- [x] credential detection
- [x] entropy-based detection
- [x] weak/deprecated crypto detection
- [x] redaction
- [x] salted fingerprint storage
- [x] redaction persistence test
- [x] normalized finding schema
- [x] tests/evidence

DAY 3 GATE:
Controlled vulnerable fixtures produce real non-weaponized findings.

## Day 4 — Integration + Product

- [x] orchestrate complete pipeline
- [x] finish REST API
- [x] filesystem endpoint
- [x] binary-audit endpoint
- [x] vulnerabilities endpoint
- [x] report endpoint
- [x] job-status endpoint
- [x] dashboard
- [x] firmware/job status
- [x] file-tree viewer
- [x] mitigation matrix
- [x] CFG viewer
- [x] finding/crash log
- [x] OpenTelemetry
- [x] audit trail
- [x] reports
- [x] API documentation/examples
- [x] integration tests

DAY 4 GATE:
One controlled image flows through the entire application.

## Day 5 — Validation + Submission

- [ ] permitted public/open-source firmware E2E test
- [ ] extraction success measurement
- [ ] checksec spot checks
- [ ] containment proof
- [ ] quota-termination proof
- [ ] redaction proof
- [ ] symbolic/taint sample finding
- [ ] CWE validation
- [ ] performance measurement
- [ ] test coverage
- [ ] recorded E2E demonstration
- [ ] architecture document
- [ ] architecture diagram
- [ ] README
- [ ] setup guide
- [ ] runbook
- [ ] testing guide
- [ ] security/containment documentation
- [ ] known limitations
- [ ] final write-up
- [ ] final requirements traceability
- [ ] final validation matrix

OPTIONAL/SHOULD AFTER CORE:
- [ ] protocol-aware HTTP fuzzing
- [ ] UPnP fuzzing
- [ ] MQTT fuzzing
- [ ] stronger full-system firmware support

FINAL GATE:
No "complete" status until ACCEPTANCE.md and final-validation.md are satisfied
with real evidence.

## PRD extraction additions — planning baseline 2026-10-19

See REQUIREMENTS.md for exact obligations, docs/requirements-gap-analysis.md for omissions in the original checklist, and docs/implementation-plan.md for sequencing. Original checklist items above remain; the index below adds every extracted requirement without weakening a Must.

- [x] Read complete PRD including tables and Appendices A–D; record source hash/text.
- [x] Extract 112 stable requirement records with priority basis, implementation, verification and evidence plans.
- [x] Populate all traceability entries as NOT STARTED and inspect environment without modification.
- [x] Compare task/acceptance coverage and publish five-day plan.
- [ ] No implementation begins in the planning milestone; resume only on the next implementation instruction.

Priority notes: five Should requirements remain scheduled, including best-effort full-system/stubs. Snapshot/restore is Could. The old “OPTIONAL/SHOULD AFTER CORE” heading does not remove Should items from the execution plan. Contained HTTP/UPnP/MQTT networking is Must, even when arbitrary firmware service boot fails.

The following additions are explicit tasks; each canonical ID carries its detailed verification and evidence obligations. Nothing below is completed by writing this checklist.

### Day 1 requirement checklist

- [ ] FWX-SCOPE-001 (Must) — Only public open-source IoT firmware licensed for analysis; Linux router/camera firmware first, MIPS/ARM priority.
- [x] FWX-SCOPE-002 (Must) — No live/physical devices or real/third-party networks; analyse image files only.
- [x] FWX-SCOPE-003 (Must) — Exclude kernel, bootloader and driver exploitation; focus user-space binaries/services.
- [x] FWX-SCOPE-004 (Must) — Never generate functional exploits, weaponised PoCs or shellcode; diagnostic findings for human validation only.
- [ ] FWX-SCOPE-005 (Must) — Do not distribute proprietary IP or real secrets.
- [x] FWX-ARCH-001 (Must) — Modular control plane, extractor, emulation controller, dynamic/symbolic runner and secret/crypto scanner; heavy stages via isolated quota-bound queue workers.
- [x] FWX-ARCH-002 (Must) — PostgreSQL stores metadata/findings/mitigation matrix; Redis coordinates queued work.
- [ ] FWX-ARCH-003 (Must) — Choose and justify free/open-source stack tools; Python analysis with C/C++ where native hooks/performance require it.
- [x] FWX-STATIC-001 (Must) — Identify containers and carve SquashFS, CramFS, UBIFS, JFFS2, cpio and ext, including multistage compression and custom/vendor headers.
- [x] FWX-STATIC-002 (Must) — Include entropy analysis in Binwalk unpacker.
- [x] FWX-STATIC-003 (Must) — Reconstruct rootfs and inventory path, type, size and hash.
- [x] FWX-STATIC-004 (Must) — Enumerate executables and shared libraries; detect architecture, endianness and bitness per ELF.
- [x] FWX-STATIC-005 (Must) — Audit every ELF: NX/DEP, canaries, RELRO none/partial/full, PIE/ASLR capability, FORTIFY and stripped; persist/emit matrix.
- [x] FWX-OBS-001 (Must) — Immutable append-only audit log of every job input, parameters, artifacts and findings.
- [x] FWX-API-001 (Must) — POST /api/v1/firmware/upload: Ingest raw .bin/.img, return firmware ID and queue analysis.
- [x] FWX-API-002 (Must) — GET /api/v1/firmware/{id}: Return image status and summary.
- [x] FWX-API-003 (Must) — GET /api/v1/firmware/{id}/filesystem: Return reconstructed inventory.
- [x] FWX-API-004 (Must) — GET /api/v1/firmware/{id}/binary-audit: Return per-ELF architecture, endianness, bits and hardening matrix.
- [x] FWX-API-007 (Must) — GET /api/v1/jobs/{jobId}: Return job status and telemetry.
- [ ] FWX-DELIV-001 (Must) — Version-controlled modular repository, clear commit history and documented PR workflow.
- [x] FWX-GOV-001 (Must) — Daily written yesterday/today/blockers stand-up.
- [ ] FWX-GOV-003 (Must) — All changes land via PR; sandbox, quota and redaction code receive extra scrutiny.
- [ ] FWX-GOV-004 (Must) — Book mentor pairing early on unpacking edge cases and symbolic budgets.

### Day 2 requirement checklist

- [ ] FWX-ARCH-004 (Must) — QEMU/Unicorn emulation architecture, angr analysis and extensible common-case firmware support.
- [x] FWX-EMU-001 (Must) — Containerized QEMU user-mode execution for MIPS, ARM32, ARM64 and x86_64.
- [x] FWX-EMU-002 (Must) — Represent MIPSEL distinctly alongside MIPS, ARM32, ARM64 and x86_64.
- [ ] FWX-EMU-003 (Should) — Best-effort full-system userland/service bring-up, NVRAM/peripheral stubs and graceful fallback; completeness not guaranteed.
- [x] FWX-EMU-004 (Must) — Contained non-routed network reaching emulated HTTP/web, UPnP and MQTT services.
- [ ] FWX-SAFE-001 (Must) — All analysis stages and execution/emulation isolated; workers have zero external egress, proven by test.
- [ ] FWX-SAFE-002 (Must) — No service or fuzzing packet escapes analysis network.
- [x] FWX-SAFE-003 (Must) — Least privilege, restricted syscalls and denied host access.
- [x] FWX-SAFE-004 (Must) — Per-job CPU/memory/wall limits with termination on breach.
- [x] FWX-SAFE-005 (Must) — Concurrency and queue back-pressure prevent aggregate exhaustion; remain responsive under load.
- [ ] FWX-SAFE-009 (Must) — Mentor signs off isolation and quotas before untrusted binary emulation.
- [x] FWX-DELIV-008 (Must) — Sandbox profiles, egress-deny configuration, quota enforcement and tests.

### Day 3 requirement checklist

- [x] FWX-STATIC-006 (Should) — Flag banned-function usage and writable/executable segments as downstream risk leads.
- [x] FWX-SYM-001 (Must) — angr paths from network/CGI parameters and environment to strcpy, memcpy, sprintf, system and popen.
- [x] FWX-SYM-002 (Must) — Track attacker-controlled data to sinks; report tainted path and reaching condition.
- [x] FWX-SYM-003 (Must) — Diagnostic faulting address, registers, stack/heap overflow offset, call path and candidate CWE for human validation.
- [x] FWX-SYM-004 (Must) — Path/state/depth/time/memory budgets, pruning and merging; partial results explicitly incomplete.
- [x] FWX-SECRET-001 (Must) — Pattern and entropy detection of hardcoded API keys, credentials/passwords, private keys and certificates.
- [x] FWX-SECRET-002 (Must) — Detect weak/deprecated crypto and hashes including security-context MD5/SHA-1.
- [x] FWX-SAFE-006 (Must) — Automatically redact secrets, keys, passwords, certificates and proprietary IP/strings in stored/displayed output; no plaintext secrets persisted by default.
- [x] FWX-SAFE-007 (Must) — Salted hash/fingerprint references retain actionability without secret values.
- [x] FWX-SAFE-008 (Must) — Any unredacted artifact access/reveal authorized and audited.
- [x] FWX-SCHEMA-001 (Must) — All findings include vulnerability_id: UUID, stable finding identifier.
- [x] FWX-SCHEMA-002 (Must) — All findings include firmware_id: UUID.
- [x] FWX-SCHEMA-003 (Must) — All findings include binary: rootfs path string.
- [x] FWX-SCHEMA-004 (Must) — All findings include architecture: enum ARM32, ARM64, MIPS, MIPSEL, x86_64.
- [x] FWX-SCHEMA-005 (Must) — All findings include category: enum memory_corruption, hardcoded_secret, weak_crypto, missing_mitigation, command_injection.
- [x] FWX-SCHEMA-006 (Must) — All findings include cwe: CWE string.
- [x] FWX-SCHEMA-007 (Must) — All findings include address: hex virtual-address string or null.
- [x] FWX-SCHEMA-008 (Must) — All findings include sink: string or null.
- [x] FWX-SCHEMA-009 (Must) — All findings include source: input-origin string or null.
- [x] FWX-SCHEMA-010 (Must) — All findings include tainted_path: array of hex addresses.
- [x] FWX-SCHEMA-011 (Must) — All findings include crash_state.fault_address: hex string or null.
- [x] FWX-SCHEMA-012 (Must) — All findings include crash_state.registers: object or null.
- [x] FWX-SCHEMA-013 (Must) — All findings include crash_state.overflow_offset: integer or null.
- [x] FWX-SCHEMA-014 (Must) — All findings include crash_state.stack_hash: string or null.
- [x] FWX-SCHEMA-015 (Must) — All findings include risk_rating: enum critical, high, medium, low, info.
- [x] FWX-SCHEMA-016 (Must) — All findings include confidence: enum confirmed, probable, heuristic.
- [x] FWX-SCHEMA-017 (Must) — All findings include evidence_ref: redacted artifact-reference string.
- [x] FWX-SCHEMA-018 (Must) — All findings include redacted: boolean.
- [x] FWX-SCHEMA-019 (Must) — All findings include status: enum new, triaged, validated, false_positive.
- [x] FWX-SCHEMA-020 (Must) — All findings include detected_at: RFC3339 UTC string.
- [ ] FWX-SCHEMA-021 (Must) — Version JSON schema; uniformly normalize static, emulation, taint and scanner findings; no exploit artifacts.
- [ ] FWX-SCHEMA-022 (Must) — Calibrated confidence, explicit heuristic labels, taint-condition evidence and dedup reduce false positives.
- [ ] FWX-SCHEMA-023 (Must) — Use reference mappings CWE-120, 121/122, 787, 134, 78, 798/259, 321, 327/328 and 1277 only where evidence supports them.

### Day 4 requirement checklist

- [x] FWX-FUNC-001 (Must) — Repeatable upload → unpack → audit → emulate → symbolic/taint → secret scan → normalize → persisted report and dashboard vertical slice.
- [ ] FWX-FUZZ-001 (Should) — Protocol-aware HTTP/UPnP/MQTT fuzzing of emulated services for crash discovery.
- [ ] FWX-FUZZ-002 (Should) — Deterministic seeded corpora, minimized crash inputs, diagnostic reproducer and emulated crash state.
- [ ] FWX-FUZZ-003 (Should) — Deduplicate crashes by stack/backtrace hash into normalized findings.
- [x] FWX-OBS-002 (Must) — OpenTelemetry traces every job stage and collects lifecycle metrics.
- [x] FWX-API-005 (Must) — GET /api/v1/firmware/{id}/vulnerabilities: Return CWEs, crash offsets and static findings.
- [x] FWX-API-006 (Must) — GET /api/v1/firmware/{id}/report: Return normalized static/dynamic/scanner report.
- [x] FWX-UI-001 (Must) — Browse reconstructed file tree with per-file metadata and hashes.
- [x] FWX-UI-002 (Must) — All-ELF NX/PIE/RELRO/canary/FORTIFY table sortable by risk.
- [x] FWX-UI-003 (Must) — Interactive CFG for selected binary/function supports taint-path review.
- [x] FWX-UI-004 (Must) — Filterable findings/crash log with CWE, risk, address/offset, confidence and redacted evidence.
- [x] FWX-DELIV-004 (Must) — Working unpacker, static audit, emulation, symbolic/taint and secret/crypto pipeline.
- [x] FWX-DELIV-007 (Must) — Dashboard and documented REST/gRPC endpoints with example requests/responses.

### Day 5 requirement checklist

- [ ] FWX-EMU-005 (Could) — Snapshot/restore emulated state for repeatable deterministic runs.
- [ ] FWX-DELIV-002 (Must) — README/runbook cover API/workers/Postgres/Redis/sandbox deployment, image submission, results and teardown.
- [x] FWX-DELIV-003 (Must) — Architecture document/diagram cover components, communication, data and containment; match code.
- [x] FWX-DELIV-005 (Must) — Versioned finding schema and real-image sample findings.
- [x] FWX-DELIV-006 (Must) — Mitigation matrix for an analyzed open-source image.
- [x] FWX-DELIV-009 (Must) — Final write-up: results, decisions, trade-offs and explicit known limitations.
- [x] FWX-TEST-001 (Must) — Automated unpacking/static/emulation/analysis/redaction tests and core-module coverage report.
- [x] FWX-EVID-001 (Must) — Repository URL/history and README/runbook.
- [x] FWX-EVID-002 (Must) — Architecture diagram matching delivered code.
- [x] FWX-EVID-003 (Must) — Named open-source image unpack, file tree and per-binary hardening table.
- [ ] FWX-EVID-004 (Must) — Real JSON taint-to-sink finding with crash state/CWE and redacted secret/crypto finding.
- [ ] FWX-EVID-005 (Must) — Screen recording from API upload to dashboard report.
- [x] FWX-EVID-006 (Must) — No-egress and quota-breach termination proof.
- [x] FWX-EVID-007 (Must) — Proof discovered secret stored only as fingerprint.
- [x] FWX-EVID-008 (Must) — Static audit plus basic-symbolic throughput measurement on representative image.
- [x] FWX-EVID-009 (Must) — Core-module coverage report.
- [ ] FWX-KPI-001 (Must) — Extraction success strictly >90% of defined standard open-source IoT firmware set.
- [x] FWX-KPI-002 (Must) — Static audit plus basic symbolic trace strictly <30 minutes per representative image.
- [ ] FWX-KPI-003 (Must) — 100% containment reliability: every analysis job sandboxed, quotas enforced, no egress/escape.
- [ ] FWX-KPI-004 (Must) — Spot-checked findings have correct CWE and calibrated confidence.
- [ ] FWX-KPI-005 (Must) — 100% redaction coverage: no raw secret persisted as plaintext output.
- [ ] FWX-DOD-001 (Must) — E2E upload to CWE report on standard open-source image, viewable in dashboard.
- [ ] FWX-DOD-002 (Must) — Unpack >90% of standard open-source set.
- [ ] FWX-DOD-003 (Must) — All execution/emulation sandboxed; zero worker egress proven.
- [x] FWX-DOD-004 (Must) — CPU/memory/time quotas enforced; breaching job terminated, proven.
- [ ] FWX-DOD-005 (Must) — Normalized findings correctly CWE-classified with confidence.
- [x] FWX-DOD-006 (Must) — Secrets redacted and fingerprint-only by default.
- [x] FWX-DOD-007 (Must) — Static audit plus basic symbolic trace under 30 minutes.
- [x] FWX-DOD-008 (Must) — Required API/dashboard views and OpenTelemetry job tracing.
- [ ] FWX-DOD-009 (Must) — Tested/documented code; new engineer reproduces run from runbook.
- [ ] FWX-GOV-002 (Must) — Weekly demo/review working increment against exit criteria.

### Repository engineering obligations retained outside PRD count

- [ ] Preserve AGENTS.md rules: upload SHA-256 identification, safe cleanup, meaningful tests/evidence after changes, and docs/final-validation.md.
- [ ] Use isolated Python 3.12 with verified hash-locked dependencies; leave system Python unchanged.
- [ ] Verify QEMU software emulation without /dev/kvm.
- [ ] Arrange Git identity/remote/PR workflow; do not claim commits or PR review before they exist.
- [ ] Keep exact mentor containment sign-off and sensitive-code reviews linked to configuration/code.
- [ ] Freeze corpus and benchmark manifest before measurement; retain failures in denominator.

Task 2 note: checked static items have scoped evidence in docs/day1-validation.md. Full job lifecycle recovery, safety gate, PR review and all later stages remain open. Broad requirement checkboxes are not automatically checked by this static slice.

Task 2 completion follow-up: stale-running-job recovery, admission saturation, static quota termination/cleanup, frozen clean migration and license inventories verified. Static engineering checks pass; human PR/mentor/corpus review pending. See docs/task2-review.md.

Task 3 engineering: Day 2 controlled execution checks are recorded in docs/task3-review.md and evidence/task3/. Checkbox completion covers the implemented, tested scope, not mentor approval or arbitrary firmware compatibility. FWX-EMU-003 remains best-effort/partial for vendor boot. Human containment and PR review remain pending; later pipeline requirements remain open.

Task 4 scoped engineering: Day 3 controlled symbolic/scanner and new finding-persistence checks are documented in docs/task4-review.md. Checked redaction/schema tasks apply to these new outputs; universal static API/log/trace/export redaction and all-producer schema integration remain open (FWX-SAFE-006, FWX-SCHEMA-021). Raw reveal is disabled. Mentor approval, sensitive-code PR review and upload-to-report/dashboard integration remain outstanding. No final DoD completion is implied.

Task 5: the controlled Day 4 vertical-slice gate passes; see docs/task5-review.md and evidence/task5/. Checked feature bullets indicate verified implemented scope. FWX-FUZZ-001–003 remain NOT STARTED, FWX-OBS-002 retains queue/persistence/failure tracing gaps. These are carried explicitly into final completion work, not waived. Mentor/PR/external publication gates remain open.

Task 6 validation pass: see docs/task6-review.md and docs/final-validation.md. Architecture, testing/security documentation, final write-up, coverage and controlled recording now exist. Corpus revalidation passes 6/6 after fixing decompression limits; persistence rollback is verified. FINAL GATE REMAINS OPEN: 71 PASS / 41 FAIL. Do not check broad acceptance boxes or claim Task 6 complete until outstanding engineering and human-gated requirements are satisfied.

## Current completion follow-up (2026-10-20)

Permitted Task 5 core integration is verified; lifecycle tracing and historical/output-boundary gaps are closed within the tested contract. Current ledger: **78 PASS / 34 FAIL**; checked requirement IDs follow that ledger. Earlier counts/notes above are historical. Optional fuzz/replay/dedup remains DEFERRED per user instruction, without a fabricated safety-policy block. Real firmware execution remains **PENDING HUMAN REVIEW**. Full PRD release is NOT ACCEPTED; see docs/completion-report.md and docs/final-validation.md.

## Controlled cross-architecture E2E follow-up

2026-10-20: all five controlled firmware images pass the full upload-to-dashboard pipeline. Reports are generated by the actual application. Evidence: docs/cross-architecture-e2e.md and evidence/cross-e2e/summary.json. Fresh regression: 85 unit tests, two pipeline cases including denied unregistered execution, eight API guards, dashboard checks and four shared-profile quota/network cases pass. This closes the controlled E2E coverage gap; it does not authorize real/vendor execution or change the 78 PASS / 34 FAIL final acceptance count.
