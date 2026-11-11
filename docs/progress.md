# FirmwareX progress

## 2026-11-11 — repository submission and report revision

Prepared a clean snapshot for the user-supplied Unit42-FirmwareX repository while preserving its existing main history and Apache licence. Excluded runtime storage, credentials, downloaded firmware and videos. Publication snapshot: 170 unit tests passed, one dependency deprecation warning. Known-credential and GitHub-token-pattern scan found no matches. Revised the project report with embedded fonts, larger screenshots and simpler writing; visually checked all 11 pages. Existing acceptance limits remain unchanged. Publication evidence is in evidence/publication-2026-11-11; local videos remain separate submission artifacts.

## 2026-11-10 — paced employee-to-report recording

Recorded a 6:01 automated walkthrough: registration/login, actual local OpenWrt folder view, checksum-verified real upload, dashboard features, report/JSON exports and logout. New assessment completed with 1,571 entries, 171 binaries and 20 candidates. Exact server JSON, HTML, chapter timestamps, video and hashes are in `evidence/employee-firmware-walkthrough-2026-11-10/`. Native OS picker is outside browser capture; real folder listing is shown through a temporary loopback server, now stopped. Failed take archived under ignored work/recording-retakes. No human-recorded claim; no secrets in text exports.

## 2026-11-10 — employee registration and login

Implemented user-requested employee ID/password login and shared company-code registration; additive PostgreSQL migration, hashed passwords, expiring/revocable cookie sessions, same-origin mutation checks and Redis attempt limits. Updated instance on port 8001; existing real firmware report retained. Full suite: 170 passed; actual browser registration/login/refresh/logout/mobile checks passed. Initial missing-fixture-mount run retained separately. See `docs/employee-access.md` and `evidence/employee-access-2026-11-10/`. No unrelated requirement statuses changed.

## 2026-11-10 — fresh real-image evidence

Current submission — 2026-11-10: **159 unit tests passed; selected OpenWrt checks complete.** Static plus selected analysis: **4.209340868 seconds**. Requirement ledger: **105 PASS / 7 FAIL**. Real-image crash validation and independent clean-machine reproduction remain open. See `docs/submission-2026-11-10.md` for evidence and reproduction. Fresh empty instance, dashboard video/HTML/JSON, persistence after restart and recoverable cache cleanup verified. Browser recording now preserves exact JSON integer timestamps.

## 2026-11-09 — Neutral execution wording and stage details

Removed mentor wording from the dashboard, public reports and execution rejection
messages. Public output translates historical authorization values into neutral
execution labels while retaining legacy internal configuration compatibility.
Added expandable per-binary stage results and plain-language reasons for runtime
and symbolic limitations. Analysis outcomes and execution isolation are unchanged.
Validation: 155 unit tests passed; verify-stage-details.cjs passed against the saved
OpenWrt report, checking no mentor wording in the page/API and preserved incomplete
status. Rebuilt and restarted the control services. Complete real-firmware dynamic
coverage still requires service profiles and supported symbolic startup/library models.

## 2026-11-09 — Runtime regression recheck

Corrected a regression introduced by aed4c69: the trusted output sanitizer required
a salt that standalone emulation/snapshot jobs did not create. The launcher now
creates a private per-job salt when absent and reuses existing firmware salts;
invalid and symlink salts are rejected before launching a workload. Added explicit
diagnostic vocabulary for console hashes, fallback reasons and containment probes.
Fixed the snapshot verification script to ignore registry license metadata.

Fresh verification: 154 unit tests passed; 36 real emulation checks passed across
five architectures; two snapshot restores passed; five output-quota/invalid-output
cases passed; a new unsanitized-worker probe proved redaction before persistence
and cleanup. Two queued pipeline cases passed: controlled firmware completed with
9 findings; the other fixture correctly retained partial status with 3 findings.
Runtime evidence is in evidence/recheck-2026-11-09/. The control image was rebuilt
and the local services restarted. These checks do not establish complete vendor
symbolic analysis; the previous blanket completion statement was too broad.

The fresh real OpenWrt browser check also passed: upload, static/scanner findings,
actual uhttpd loopback HTTP response and dashboard/report display. Its overall
analysis remains partial because vendor dynamic coverage is bounded. Saved
report, screenshot and recording: evidence/recheck-2026-11-09/openwrt/.

## 2026-11-09 — Submission evidence consolidation

Added a reproducible labeled classification sample, delivery baseline check and acceptance coverage audit. The sample checks static API leads, modeled taint-to-sink and null-write findings, credential candidates, and crypto candidates against their declared source/evidence rules. The coverage audit assembles four sandbox-scope quota/no-egress/cleanup checks, bounded output cases, redacted persisted reports and committed evidence scanning. The delivery baseline checks repository history and documented workflow. The ledger now records **102 PASS / 10 FAIL**. Remaining failures require a real-image supported dynamic finding, completed representative symbolic trace, independent reproduction, and genuine human mentor/review/PR/pairing records.

## 2026-11-08 — Acceptance-contract and containment verification

Added a shared symbolic budget contract used by both the direct engine and trusted controller, with invalid-number and ceiling tests. Added schema/runtime validation over 10 stored reports and 179 findings. Real symbolic regression now verifies a negative case, a tainted bounded write and a null write mapped to CWE-476 with a zero fault address. Static, emulation, analysis and pipeline sandbox probes passed CPU, memory, wall, network, privilege and cleanup checks. Provenance manifests and committed evidence passed the license/sentinel audit. Current ledger: **95 PASS / 17 FAIL**; acceptance remains NOT ACCEPTED pending the documented human and representative-real-image obligations.

## 2026-11-08 — Hardening, optional stages and real OpenWrt service evidence

Completed the user-authorized follow-up: blocking upload work moved to the thread pool; bounded output tmpfs/archive copying; source-model boundary fixes; stage-error preservation; scanner context/certificate/entropy accuracy fixes; trusted mentor execution configuration; guest-local symlink resolution; bounded executable sampling and symbolic children; preserved-original reanalysis API/UI; controlled protocol fuzz/minimization/replay/dedup and ARM snapshot restore. New real OpenWrt profiles verify BusyBox and uhttpd serving a synthetic page. Fixed HTTP 403 caused by restrictive synthetic-page permissions without changing firmware permissions or sandbox policy.

Verification: 128 unit tests passed in 9.49 seconds; whole-package unit coverage 35.94% (716/1,992 lines), excluding separately executed integration tests. Earlier hardening evidence records 13 source-model cases, five output quota cases, four production resource/network cases, concurrent upload responsiveness, 42 symbolic/36 emulation cases and five-architecture integration. Fresh optional results: 12 protocol trials with verified replay/common-stack dedup; two ARM snapshot restores; both optional full queued pipelines complete. Six frozen OpenWrt images pass the declared extraction/static rule. Current dashboard passes ten interaction groups. Actual x86 OpenWrt upload produces 1,571 entries, 171 ELF binaries and 20 candidate findings; uhttpd HTTP harness passes. Symbolic sampling remains incomplete and no real-image taint crash is claimed.

Commands: Docker pipeline/control/fixture builds; pytest with XML/coverage; verify-source-models.py, verify-output-quota.py, verify-concurrent-uploads.py, verify-pipeline.py, verify-fuzz.py, verify-snapshots.py, verify-extended-pipeline.py, verify-final-corpus.py, verify-demo-reanalysis.py, verify-dashboard.cjs and verify-openwrt-demo.cjs. WebM last frame decoded using the bundled FFmpeg and visually checked. Initial FFmpeg null-output check was unsupported by that bundled build; image-frame decoding succeeded. Application services were stopped on resumption; docker compose up -d restored them before pipeline/browser validation.

Evidence: evidence/hardening-2026-11-07/ and evidence/mentor-accuracy-2026-11-07/, including service-verified/, openwrt-demo/, regression/, corpus/, unit-tests.xml and validation-counts.json. Added hardening-validation.md, release-readiness.md and mentor-authorization.md; updated acceptance/traceability/architecture. New scoped PASS rows: EMU-003/005, FUZZ-001/002/003, EVID-005, KPI-001, DOD-001/002. All 112 IDs retained: 87 PASS / 25 FAIL. Remaining work includes real-image taint/crash evidence, representative symbolic performance, classification calibration, containment/redaction denominator audits, provenance/dependency review and independent reproduction/PR/milestone review. Local mentor authorization does not fabricate independent acceptance. No external publication or messages.

## 2026-10-19 — Specification extraction and implementation planning

**Milestone complete: planning only. Implementation stopped as requested.**

### Completed work

Located repository at /home/ubunt/projects/firmwarex (the chat working directory was empty). Read AGENTS.md, TASKS.md, ACCEPTANCE.md and existing empty docs. Read all PRD body paragraphs and tables, Appendices A–D, header/footer, and confirmed empty notes/comments and no embedded drawings/tracked changes/alternate content. Saved full numbered source text and SHA-256.

Created 112 stable records: 106 Must (10 explicit MoSCoW, 96 inferred obligations), 5 Should (one explicitly best-effort), 1 Could. Each has PRD location, requirement, priority basis, planned implementation/test/evidence and execution day. Added complete traceability, gap analysis, additive task/acceptance checklists and five-day plan preserving every Must and original milestone exit gate.

Inspected OS/CPU/RAM/disk, Docker/Compose/daemon security metadata, Git/Python and virtualization without destructive changes. Selected proposed isolated Python 3.12 runtime using official documentation and actual PyPI metadata; recorded dependency candidate and validation still required.

### Files created or changed

Created REQUIREMENTS.md; docs/implementation-plan.md, requirements-gap-analysis.md, environment.md; evidence/planning/prd-full-text.txt, environment.json, dependency-metadata.json, requirements-index.json, document-validation.json, validate_planning.py, TASKS.before.md and ACCEPTANCE.before.md.

Populated docs/requirements-traceability.md, progress.md, decisions.md and known-limitations.md. Appended to TASKS.md and ACCEPTANCE.md; marked the three completed original planning items checked. All other original content is retained. PRD.docx, AGENTS.md and empty REQUREMENTS.md unchanged.

### Commands and verification actually performed

- Read repository files and inspected git status/log/config; no existing implementation or commits.
- Bundled Python with ZipFile/lxml read complete OOXML paragraphs/tables and checked part structure. Source hash: 03451782008d39e8003efc4ec1ba8a650ec9206a8d5aa1f99ac314467c31fd14.
- Read-only environment commands: cat /etc/os-release, uname -m, lscpu, free -h, df -h, docker --version, docker compose version, docker info, git --version, command -v, python3 --version, ls /dev/kvm, systemd-detect-virt and lsmod. Individual return codes saved; missing /dev/kvm and unborn git history are observations, not successful capabilities.
- Queried official upstream documentation and PyPI JSON metadata for angr, cle, pyvex, archinfo, claripy and Unicorn. No dependencies installed.
- Reproducible planning check: `python3 evidence/planning/validate_planning.py` — 14 checks passed, exit 0. Document checks: 112 unique IDs, 112 traceability rows, all NOT STARTED; every ID present in requirements/tasks/acceptance/plan; no unknown IDs; all 16 FR and 9 SC source identifiers represented; all required record fields present; PRD hash unchanged; original task content retained except three completed planning checkboxes; original acceptance content preserved. **PASS for document consistency only.**
- Reviewed source coverage across §§1–15 and Appendices A–D, including explicit Could priority and reference-only CWE-1277.

### Actual results and evidence

evidence/planning/document-validation.json records successful planning consistency checks. environment.json records Ubuntu 26.04.1, x86_64/8 CPUs, 7.2 GiB RAM, approximately 68 GiB disk available, Docker 29.9.1, Compose 5.6.0, Git 2.53.0, system Python 3.14.4 and absent KVM device.

**Application tests executed: none. Application requirements satisfied: none.** No firmware executed, no services started, no package installations, no system Python changes. No containment approval or security/performance/coverage claims. No commit or PR created: no configured author identity was observed and PR-only review workflow must be established.

### Remaining work and blockers

Next milestone is Day 1 as specified in implementation-plan.md, after the user's next implementation instruction. Confirm/pin runtime and native tool compatibility; establish branch/PR workflow; implement sandboxed static slice and real evidence. Select licensed corpus/representative image and concrete budgets. Arrange mentor pairing and mandatory pre-untrusted-emulation sign-off. All Must obligations retain their original scope despite five-day compression.

Daily stand-up: yesterday — initial repository inputs supplied; today — full extraction/planning/environment baseline; next — Day 1 foundation/static pipeline; blockers — none for planning, untrusted emulation gated by future mentor approval.

## 2026-10-19 — Task 2 foundation and static slice

User authorized implementation and supplied local Git identity/remote; external GitHub mutations remain prohibited without approval. Branch: implementation/day1-static. Local planning baseline committed before implementation commit. No push, PR, merge or publication.

Implemented FastAPI authenticated upload and five static milestone routes; SHA-256 identity/provenance/admission limit; PostgreSQL migrations and inventory/audit persistence; Redis/Celery dispatcher with queued-job redispatch; offline one-shot extraction with CPU/memory/wall settings; Binwalk signatures/entropy, six filesystem adapters, multistage/custom-header carving, metadata-only special inodes; inventory and ELF architecture/hardening analysis. Added digest-pinned images, hash locks, private bootstrap, source fixtures and reproducible verification scripts.

Actual verification:
- 13 unit tests passed under isolated Python 3.12.15, including four cross-compiled architecture cases; test XML and coverage recorded.
- Three real upload/queue/offline-sandbox/persistence/API cases passed; five additional filesystem format cases passed.
- Frozen OpenWrt corpus 6/6 (100%) static extraction successes; 171/171/186/209/153/153 ELF matrices across six images. This is project-corpus evidence, with final standard-set reviewer agreement pending.
- Three compiler variants matched checksec across six hardening fields.
- Authentication/missing-ID/UUID guards passed. Runtime DB role denied UPDATE/DELETE/TRUNCATE on audit log; lifecycle records verified.
- Static profile probe verified nonroot/no capabilities/loopback only/no default route/no Docker socket/read-only root. Full containment/quota-breach gate remains unverified.
- Actual angr import/CFG (33 functions), Z3 solver and controlled Unicorn NOP smoke passed with Python 3.12.15, angr 10.0.4.post1 and Unicorn 2.1.4. Both control and analysis pip check passed. Host Python unchanged.

Evidence and exact reproduction: docs/day1-validation.md and evidence/day1/. Failed build/test attempts retained with successful reruns. Implementation paths and scoped PASS/IN PROGRESS statuses updated in requirements-traceability.md; no broad application completion claim.

Requirements with scoped static evidence: FWX-STATIC-001–005, FWX-API-001–004, FWX-KPI-001. Broader architecture, audit, job telemetry, containment and delivery records remain IN PROGRESS. No final DoD condition marked complete.

Remaining: mentor pairing/PR review, full containment and termination verification, stale-running-job recovery, universal redaction, observability, emulation/symbolic/fuzzing/findings/dashboard and remaining PRD delivery/evidence. Six-image corpus must be reviewed before final acceptance. No arbitrary firmware binary execution or emulation occurred.

Daily update: completed static spine and evidence; next containment/QEMU milestone after these local changes are reviewed; blocker for untrusted emulation is mandatory mentor sign-off.

## 2026-10-19 — Task 2 engineering completion follow-up

User requested closing Task 2 gaps. Implemented stale-running-job recovery with explicit failure/audit and orphan cleanup; froze initial migration DDL; corrected Docker stats sampling/wall duration. Added real production-launcher quota/network/mount tests, saturation admission test, orphan recovery test, license inventory and cross-fixture recipe.

Actual results: CPU/memory/wall breaches terminated and containers removed; host TCP plus IPv4/IPv6 UDP denied; mount denied; 16-job saturation returned 429 with health 200 in 0.013 seconds; stale running job failed as dispatcher_lost with audit and orphan removal. Clean separate PostgreSQL migration, downgrade and upgrade succeeded; temporary stack stopped without deleting existing application data. Python licenses/versions inventoried (54/46/11 distributions).

Final regressions passed: 13 unit tests, three API scenarios, five extra formats, 6/6 public corpus images. Evidence: evidence/task2-completion/. Source changes: sandbox.py, tasks.py, frozen migration; scripts/verify-quotas.py, verify-recovery-admission.py, dependency-inventory.py and build-cross-fixtures.sh. All 112 requirements retained.

Task 2 static engineering is complete within the declared tested scope; formal acceptance still awaits human PR/mentor review and corpus baseline agreement. No claim of error-free software or completion of later PRD stages. The mandatory pre-untrusted-emulation sign-off remains unsatisfied. No external GitHub mutation performed.


## Task 3 — Day 2 controlled containment/QEMU milestone (2026-10-19)

Yesterday/previous milestone: static pipeline and follow-up validation delivered; review gates remained open.
Today: implemented trusted emulation controller, controlled SHA-256 registry gate, five QEMU user-mode adapters, private-loopback HTTP/UPnP/MQTT probes, named TCG full-system profiles, minimal read-only NVRAM shim, durable audit events and shared sandbox profile telemetry. Added native fixture/image builds and automated tests. No untrusted firmware was executed.

Validation: 29 unit/static regression tests, 36 real QEMU integration cases, 20 packet-observed service/containment repeat cases, durable pre-launch denial and existing four-case static quota/network regression passed. Every QEMU run checked cleanup/audit. Host capture saw only its one injected loopback positive control and zero guest/service packets, with zero drops. Controlled ARM UART boot reached its marker and timed out as designed; no vendor Linux boot claimed.

Commands: Docker builds for qemu/fixtures/observer; scripts/build-emulation-fixtures.sh; pytest test_emulation.py/test_static.py; trusted-dispatcher scripts/verify-emulation.py (normal and FWX_CAPTURE_ONLY=1), verify-emulation-gate.py, verify-quotas.py; filtered host tcpdump with an independent positive control. Evidence: evidence/task3/summary.json, integration.json, capture-integration.json, unit-tests.xml, egress.pcap and retained logs. Review/reproduction: docs/task3-review.md.

Requirements: scoped passes FWX-EMU-001/002/004, FWX-SAFE-002/003/004 and FWX-DELIV-008; other broad requirements retain their limits in traceability. FWX-EMU-003 is best-effort/partial for vendor bring-up. Next engineering milestone is Day 3 symbolic/taint and secret/crypto analysis.

Blockers: mentor containment/quotas sign-off required before arbitrary untrusted execution; sensitive-code PR review remains pending. User approval required before GitHub publication. Current controller is not yet wired into the upload pipeline (Day 4). No report/dashboard or final product acceptance claimed.

## Task 4 — Day 3 controlled analysis milestone (2026-10-19)

Previous milestone: sandboxed QEMU controlled execution and review evidence delivered; mentor sign-off pending.
Today: implemented bounded angr source/sink models, AST taint, condition/path diagnostics, ELF/DWARF/heap bounds, budget/pruning/merging controls, secret/crypto scanner, salted references, Appendix A normalization/schema, strict evidence persistence, migration 0002, controlled registry gate and denied/audited raw reveal. Added deterministic compiler fixtures and reproducible integration scripts. No arbitrary vendor binary was executed and no exploit input was generated.

Verification: 73 unit/static/emulation regression tests; source/sink/negative/budget/architecture integration matrix; two scanner persistence runs yielding eight deduplicated findings without plaintext; eight prelaunch-denial cases plus reveal denial; external watchdog termination/cleanup; clean migration roundtrip; three existing upload/static API regressions. Detailed counts/results are generated in evidence/task4/summary.json. Scoped unit coverage for findings/scanner/redaction is 92%, not whole-product coverage.

Commands: build-analysis-fixtures.sh in the compiler container; Docker analysis/control builds; pytest with JUnit/scoped coverage; verify-analysis.py, verify-redaction.py, verify-analysis-guards.py, verify-analysis-watchdog.py, verify-finding-migration.py in trusted containers; verify-api.py over local HTTP. Evidence: evidence/task4/; review: docs/task4-review.md. All 112 traceability IDs retained. Earlier failed development attempts preserved alongside successful reruns.

Requirement coverage: FWX-STATIC-006; controlled FWX-SYM-001–004, FWX-SECRET-001/002, FWX-SAFE-007/008; Appendix A field validation and scoped confidence/CWE checks. FWX-SAFE-006 and FWX-SCHEMA-021 remain IN PROGRESS for universal output sanitization and all-producer integration. No unsupported broad PASS was substituted for those obligations.

Remaining: connect components to queued upload pipeline, integrate universal sanitization, reporting/dashboard, tracing, final benchmarks and real-image acceptance. Mentor approval required before arbitrary untrusted execution; sensitive-code PR review and user approval before GitHub publication remain outstanding. The local API still advertises static_only accurately.

## Task 5 — Day 4 integration/product milestone (2026-10-19)

Previous milestone: controlled symbolic/scanner persistence verified; integration and review gates open.
Today: connected extraction, static leads, QEMU/service probes, bounded angr, scanning and normalization within one offline sandbox; added report/finding APIs, six-view responsive dashboard, real CFG interaction, local OpenTelemetry SDK records, path pseudonyms and an exact-image execution gate. Added bounded /guest staging for verified QEMU targets while retaining noexec scratch.

Verification: 78 unit/regression tests; two real upload/queue cases (controlled complete with 17 findings, unregistered partial with execution blocked); all seven required API routes; eight new API guard checks; ten browser interaction groups including redacted export/mobile; PostgreSQL/audit/output sentinel checks; four production-profile quota/network/cleanup regressions. Detailed results are in evidence/task5/summary.json and docs/task5-review.md. No untrusted execution or external GitHub write occurred.

Commands: Docker pipeline/control builds and Compose local restart; pytest; verify-pipeline.py; verify-dashboard.cjs via bundled Node/Playwright Chromium; verify-task5-api-guards.py; trusted-dispatcher verify-task5-storage.py and FWX_TEST_SCOPE=pipeline verify-quotas.py. Failed development runs were diagnosed and successful reruns retained.

Scoped coverage: FWX-FUNC-001, API-005/006, UI-001–004, DELIV-004/007; existing schema/static/safety requirements gain integrated evidence. All 112 requirement IDs remain. The Day 4 controlled vertical-slice gate passes; this does not imply final PRD compliance.

Remaining: Should fuzz/minimization/stack-dedup requirements; complete lifecycle/failure tracing; historical/universal redaction validation; final real-image/performance/coverage/corpus/recording/reproduction acceptance. These remain explicit obligations in TASKS.md/traceability, not waived by schedule. Mentor containment/quota sign-off, sensitive-code PR review, independent reviewer gates and user approval before GitHub publication remain pending.

## Usability follow-up — recognizable firmware names

User requested an easier, recognizable firmware picker. Added an explicit upload name and authenticated rename action persisted in provenance, with a fingerprint-only rename audit event. Existing unnamed images use readable sample/analysis labels and upload dates; technical IDs/checksums remain in collapsed details. Status wording is clearer. This is shared local-workspace labeling, not separate user accounts. Labels are user-entered metadata and must not contain secrets; firmware-derived names are not exposed automatically. Verification is recorded in evidence/usability/results.json and scripts/verify-friendly-names.cjs. The first rename test caught a missing audit job reference; corrected before completion. No external publication.

## Readable security report

Added a formatted assessment report alongside the JSON export: executive summary, severity counts, coverage and safety limits, binary protection matrix, severity-ordered findings with confidence/CWE/evidence, general remediation guidance, and assessment identity. Users can view it in the dashboard, download a self-contained HTML report, or print/save as PDF. Dynamic text is HTML-escaped; downloaded HTML contains no scripts, credentials or external assets. Versioned asset URLs ensure the new UI is fetched on reload.

Verification: scripts/verify-readable-report.cjs passed content escaping, 17-finding completeness, HTML download, secret/token absence, print stylesheet/PDF creation, blocked-stage disclosure and browser-error checks. Evidence: evidence/readable-report/results.json, preview.png and sample-report.html/pdf. PDF summary and findings pages visually inspected. General recommendations are explicitly not verified fixes; no CVSS or confirmed exploitation claim is fabricated. This changes presentation only, not analysis coverage or pending approval gates.

Report follow-up: final browser checks passed after local service restart; long symbolic expressions are explicitly excerpted with the full expression retained in JSON. Final sample PDF is 18 pages; the formerly sparse evidence page was visually rechecked after correction. Local-only delivery; no push.

## Task 6 — final authorized validation pass (2026-10-19)

Previous: integrated controlled pipeline, dashboard usability and readable reports delivered. Today: reran frozen public-image extraction/static/scanner corpus, controlled symbolic/emulation/guard/quota suites, storage and migration checks, whole-package unit coverage, readable-report checks and controlled video. Added architecture/diagram, testing guide, security review packet, final write-up and all-112-requirement PASS/FAIL ledger. Fixed a real 32 MiB decompression-limit regression and persistence exceptions leaving running jobs.

Results: 78 unit tests; 28.66% whole-package unit coverage; 42 symbolic cases; 36 emulation cases across five architectures; four independent pipeline quota/network cases; nine guard cases; 6/6 frozen corpus extraction, with 1,941 schema-valid real-image static/scanner candidates. Real-image reports remain partial: emulation/symbolic execution correctly blocked. Measured 4.238–5.254-second corpus wall times are NOT symbolic benchmark evidence. Atomic persistence rollback and disposable migration roundtrip passed. Details/commands/evidence: docs/task6-review.md, docs/testing.md, scripts/verify-final-*.py, evidence/task6/summary.json.

All 112 requirements preserved: 71 PASS / 41 FAIL, with scope and missing evidence stated. Task 6/final acceptance remains incomplete. Requested mentor sign-off details; no approval presumed. Outstanding engineering includes full lifecycle tracing, universal/historical redaction validation and Should fuzz/replay/dedup. Real-image dynamic evidence, independent reproduction and human PR/corpus/review gates remain pending. No untrusted execution and no external GitHub action performed.

## Task 5 required completion follow-up (2026-10-20)

Previous: controlled integrated pipeline delivered; lifecycle tracing and historical output redaction remained open. Today: added upload/queue/sandbox/persistence propagation, content-free failure and recovery telemetry, shared diagnostic vocabulary/filter, API protection for legacy records, privileged metadata cleanup with restricted originals, and artifact hashes in append-only audit. Updated telemetry display and browser evidence paths. Optional unfinished crash-testing work was set aside under ignored work/deferred-fuzz; no safety-policy block occurred and no crash operation was retried.

Verification: **85 unit tests pass**, 32.81% whole-package unit coverage; two real queued cases (17 findings/complete on the controlled fixture, 3 findings/partial on the unregistered fixture); 11 linked spans; three injected infrastructure failures with real DB persistence; admission/orphan recovery; audit UPDATE/DELETE/TRUNCATE denial; four adversarial legacy API surfaces and historical cleanup (22,208 metadata records, 47 output files); eight API guard cases; ten dashboard and eight readable-report check groups. PDF first page rendered/visually checked. New storage/audit output hashes and plaintext-sentinel checks pass. Prior unchanged 42 symbolic/36 emulation/four quota/6-image corpus results reused rather than rerun.

Commands: control/pipeline Docker builds; Compose restart; pytest with whole-package coverage; verify-pipeline.py, verify-lifecycle.py, verify-recovery-admission.py, verify-output-boundary.py through the migration role, verify-database.py, verify-task5-storage.py, API guards and Playwright dashboard/report scripts. Output in evidence/completion/. Resolved development failures: readiness race, analysis-image database-only import, attempted protected evidence update. Evidence maintenance now validates immutable evidence instead of rewriting it.

Requirement closure: FWX-FUNC-001, DELIV-004, OBS-001/002, SAFE-006, DOD-006/008 within the documented tested scope. All 112 requirements retained: **78 PASS / 34 FAIL**, full project NOT ACCEPTED. Permitted Task 5 core passes; Should fuzz/replay/dedup and Could snapshots remain deferred per user priority. Real firmware execution remains **PENDING HUMAN REVIEW**; corpus/calibration/reproduction/milestone/PR gates and universal KPI evidence remain open. No external publication/communication. Final report: docs/completion-report.md; current ledger: docs/final-validation.md.

## Per-architecture software-rendered report exports (2026-10-20)

User requested FirmwareX-produced reports for all tested architectures. Added scripts/export-architecture-reports.cjs, which invokes the unmodified application securityReport renderer and print CSS. Exported five PDF/HTML/JSON sets: x86_64 uses the recorded integrated 17-finding assessment; ARM32/ARM64/MIPS/MIPSEL each use their recorded one-finding symbolic component result. Component reports explicitly mark integrated analysis not performed, missing inventory/image identity metadata, and pending real-firmware review. No source findings altered, no tests rerun, no DB records fabricated. Source/renderer hashes and PDF verification are in evidence/architecture-reports/. All 30 PDF pages rendered and visually reviewed; text/finding counts verified. Deliverables are in the chat workspace output/pdf/software-architecture-reports, with a combined ZIP alongside. No acceptance status changed or external publication performed.

## Full controlled cross-architecture pipeline (2026-10-20)

Previous: x86_64 full pipeline; ARM32/ARM64/MIPS/MIPSEL had only component report exports. User requested complete controlled E2E coverage without real-firmware execution. Packaged deterministic SquashFS images using existing hash-registered project-owned service/taint artifacts and fake scanner data. Built each new image twice and verified matching hashes; added only four exact controlled image hashes. No analyzer/gate logic changed and no findings hard-coded.

Actual HTTP upload -> queue -> extraction/inventory/ELF/hardening -> QEMU user-mode plus HTTP/UPnP/MQTT -> bounded symbolic -> scanner -> redaction/normalization -> PostgreSQL -> API/dashboard -> software report passed on all five architectures. x86_64: 17 findings; ARM32, ARM64, MIPS and MIPSEL: 16 each, all schema-validated (81 total). All jobs complete with 11 linked trace spans. Database/artifact/audit redaction and cleanup passed. Actual dashboard exported all five HTML/PDF reports; 86 PDF pages rendered and visually reviewed. Fresh regression: 85 unit passes, x86 integrated + unregistered denied pipeline cases, eight API guards, dashboard/mobile/export; four shared-profile CPU/memory/wall/network cases pass. Evidence consistency gate passes.

Commands/scripts: Docker controlled fixture packaging and pipeline build; Compose startup; verify-cross-e2e.py; dispatcher verify-cross-e2e-storage.py and FWX_TEST_SCOPE=pipeline verify-quotas.py; Playwright verify-cross-e2e-reports.cjs; pytest; existing pipeline/API/dashboard regression; offline verify-cross-e2e-evidence.py. Saved evidence under evidence/cross-e2e/, report docs/cross-architecture-e2e.md. Source/image hashes in runtime-provenance.json. Initial setup permission/readiness failures resolved and recorded; no per-architecture analyzer failure.

Relevant requirement evidence strengthened: FUNC-001, STATIC-003, EMU-001/002/004, SYM-001/002, SAFE-003/004/006, API-005/006, OBS-002, DELIV-004, DOD-006/008. Full PRD count stays 78 PASS / 34 FAIL. FWX-SAFE-009 unchanged; real/vendor dynamic execution PENDING HUMAN REVIEW. QEMU executes benign service fixtures, symbolic analysis uses separate taint fixtures; non-x86 CWE-78 diagnostics do not claim native crashes. No optional expansion or external publication.
# OpenWrt review corrections (2026-11-09)

Corrected the regressions in 3d07176 without deleting old reports or data. Generic images again run their bounded `--help` startup probe, which remains incomplete service coverage. `complete_profile` now records objective reachability separately as `profile_status` and preserves the actual engine status, every finding, and every evidence item. The selected CGI environment supplies concrete POST/zero length, only symbolic CONTENT_TYPE, absent-variable nulls, stable repeated getenv values, and an actual symbolic filesystem cwd of `/`. Memory faults from function-entry models remain visible as heuristic diagnostics requiring validation.

Validation: 158 unit tests passed (including generic startup scheduling and preservation/status regression tests); six current controlled classification cases passed; the new compiled environment fixture passed real angr checks for argv, absent/concrete variables, stable getenv pointers, and environment-to-copy flow. Used isolated Docker runs with network disabled and source mounted read-only; compiled the project-owned fixture with gcc without executing it on the host. Rebuilt pipeline/control images and restarted Compose with volumes retained. Final Playwright upload -> extraction -> HTTP probe -> symbolic -> save -> dashboard/report passed, saved in `evidence/openwrt-review-fixed-final-2026-11-09/`.

Actual final outcome: emulation completed for selected checks; symbolic incomplete, objective reached, depth budget and model-fault validation limits preserved; job partial and UI Needs review. No whole-firmware completion claim or acceptance status changed. This strengthens FWX-FUNC-001 and bounded symbolic/partial reporting evidence. Full CGI initialization/filesystem support, concrete validation of vendor candidates, and wider firmware coverage remain open. Reproduction details: `docs/openwrt-supported-profile.md`.

## OpenWrt symbolic model correction (2026-11-09)

Corrected the `cgi-io` function-entry model without deleting prior evidence. The model now supplies writable `__errno_location` storage, returns EOF for the declared zero-length request, constrains only the documented multipart header prefix, and tracks symbolic `malloc(strlen(input)+N)` capacity through prefix copies. The previous taint-only `strcpy` candidate is no longer reported as CWE-120: the selected code allocates `strlen(boundary)+3`, then writes `--`, the boundary, and its terminator exactly within that allocation.

Validation: 159 unit tests passed. Isolated analysis regressions passed for named argv/environment behavior, writable errno, empty standard input, safe `strlen(input)+3` copy (no finding), and intentionally undersized `strlen(input)+2` copy (CWE-122). The exact OpenWrt `cgi-io` binary completed in 54 steps, one path, and zero symbolic findings. A fresh browser upload through extraction, selected emulation, symbolic analysis, persistence, and dashboard completed with `Selected checks complete`; evidence is in `evidence/openwrt-symbolic-fixed-2026-11-09/`.

Scope remains narrow: this result covers only the selected multipart-header/empty-body path and selected service checks, not every firmware binary, CGI body path, filesystem behavior, or authentication flow.
