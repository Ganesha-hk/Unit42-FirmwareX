# FirmwareX extracted requirements

Authority: PRD.docx v1.0, SHA-256 `03451782008d39e8003efc4ec1ba8a650ec9206a8d5aa1f99ac314467c31fd14`. Read completely on 2026-10-19: 648 body paragraphs including 28 tables, Appendices A–D, header/footer and empty comments/footnotes/endnotes. Full numbered text: `evidence/planning/prd-full-text.txt`. No embedded drawings, tracked changes or alternate-content parts were present.

Implementation, verification and evidence entries below preserve the extracted plan. Current implementation status and actual evidence are maintained in docs/requirements-traceability.md; Task 2 has verified a scoped static slice, not the complete application.

## Priority and counting conventions

**112 records: 106 Must (10 explicitly labelled, 96 inferred mandatory obligations), 5 Should, 1 Could.** One Should (FWX-EMU-003) is explicitly best-effort. There is no separate Best-effort priority in the PRD. FR-2.4 snapshot/restore is explicitly Could and is preserved as such. Evidence and DoD restatements have separate IDs, so the count is traceable obligations, not unique product features.

For unqualified safety, architecture, deliverable, evidence and acceptance obligations, “Must” is a conservative planning inference, explicitly identified per record. It does not assert a literal MoSCoW label in the PRD. No Must is downgraded for the five-day schedule. IDs are permanent: add new IDs for newly discovered obligations; do not renumber existing records.

## Interpretation boundaries

- §§1–3 vision, personas and learning outcomes describe capabilities specified elsewhere; they do not require a separate user-role product or every named tool.
- §9 says choose within layers and justify: Celery/RQ and REST/gRPC are alternatives. Kubernetes/KVM are not unconditional deployment prerequisites. Software QEMU remains supported as explicitly directed by the user.
- Plan Ghidra and Unicorn adapter roles, with QEMU and angr as primary engines. Triton and AFL++ are reference/alternative choices, not mandatory additional engines.
- Appendix B is a classification reference (including CWE-1277), not a new secure-update detector requirement. Preserve mappings without inventing unsupported findings.
- Appendix C defines terminology; Appendix D is recommended reading. Neither adds separate runtime features.
- The user's five-day schedule replaces four-week timing; all original milestone exit criteria remain.
- The PRD does not name the standard corpus, representative image, numerical coverage threshold, budget values, or reviewer identity. These remain explicit planning decisions; never fabricate measurements.
- Source/condition and call-path details not present as Appendix A fields belong in referenced diagnostic evidence; do not silently alter the prescribed schema.

## FWX-SCOPE-001

- **PRD section:** Document Control; §§2, 4.1–4.3
- **Requirement:** Only public open-source IoT firmware licensed for analysis; Linux router/camera firmware first, MIPS/ARM priority.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** Provenance/license manifests and input policy.
- **Planned verification:** Review real-image license; reject disallowed manifest.
- **Required evidence:** `evidence/scope/policy-review.md`
- **Execution day:** 1

## FWX-SCOPE-002

- **PRD section:** Document Control; §§2, 4.1–4.3
- **Requirement:** No live/physical devices or real/third-party networks; analyse image files only.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** Constrain inputs and sandbox interfaces.
- **Planned verification:** Inspect ingress and attempt forbidden device/network access.
- **Required evidence:** `evidence/scope/policy-review.md`
- **Execution day:** 1

## FWX-SCOPE-003

- **PRD section:** Document Control; §§2, 4.1–4.3
- **Requirement:** Exclude kernel, bootloader and driver exploitation; focus user-space binaries/services.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** Restrict analysis targets; document scope.
- **Planned verification:** Review selection and diagnostic outputs.
- **Required evidence:** `evidence/scope/policy-review.md`
- **Execution day:** 1

## FWX-SCOPE-004

- **PRD section:** Document Control; §§2, 4.1–4.3
- **Requirement:** Never generate functional exploits, weaponised PoCs or shellcode; diagnostic findings for human validation only.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** Diagnostic artifact allowlist; no exploit generator.
- **Planned verification:** Inspect artifacts and generation paths.
- **Required evidence:** `evidence/scope/policy-review.md`
- **Execution day:** 1

## FWX-SCOPE-005

- **PRD section:** Document Control; §§2, 4.1–4.3
- **Requirement:** Do not distribute proprietary IP or real secrets.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** Restricted raw input/rootfs storage; sanitized exports.
- **Planned verification:** Review exported evidence for prohibited contents.
- **Required evidence:** `evidence/scope/policy-review.md`
- **Execution day:** 1

## FWX-FUNC-001

- **PRD section:** §§1.1–1.2, 2, 5.2, 10 Week 4
- **Requirement:** Repeatable upload → unpack → audit → emulate → symbolic/taint → secret scan → normalize → persisted report and dashboard vertical slice.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** src/firmwarex/pipeline with deterministic manifests and stage status.
- **Planned verification:** Run permitted image twice; compare normalized results.
- **Required evidence:** `evidence/e2e/run-manifest.json`
- **Execution day:** 4

## FWX-ARCH-001

- **PRD section:** §§5.1–5.2, 9, 10 Week 1
- **Requirement:** Modular control plane, extractor, emulation controller, dynamic/symbolic runner and secret/crypto scanner; heavy stages via isolated quota-bound queue workers.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** FastAPI/Celery and typed artifact contracts.
- **Planned verification:** Queue/stage dependency and isolation integration.
- **Required evidence:** `evidence/architecture/flow-validation.json`
- **Execution day:** 1

## FWX-ARCH-002

- **PRD section:** §§5.2–5.3, 9
- **Requirement:** PostgreSQL stores metadata/findings/mitigation matrix; Redis coordinates queued work.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** SQLAlchemy/Alembic; Redis broker on control network.
- **Planned verification:** Migration and persistence/retrieval integration.
- **Required evidence:** `evidence/integration/persistence.json`
- **Execution day:** 1

## FWX-ARCH-003

- **PRD section:** §9
- **Requirement:** Choose and justify free/open-source stack tools; Python analysis with C/C++ where native hooks/performance require it.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** Dependency/license manifest and native CLI adapters.
- **Planned verification:** Review locks, licenses and choices.
- **Required evidence:** `evidence/dependencies/manifest.json`
- **Execution day:** 1

## FWX-ARCH-004

- **PRD section:** §§5.1, 9, 14
- **Requirement:** QEMU/Unicorn emulation architecture, angr analysis and extensible common-case firmware support.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** QEMU primary; bounded Unicorn adapter; Ghidra headless CFG adapter; justify reference-tool choices.
- **Planned verification:** Adapter contracts and architecture review.
- **Required evidence:** `evidence/architecture/adapters.md`
- **Execution day:** 2

## FWX-STATIC-001

- **PRD section:** §6.1 FR-1.1; §§5.1, 10 Week 1
- **Requirement:** Identify containers and carve SquashFS, CramFS, UBIFS, JFFS2, cpio and ext, including multistage compression and custom/vendor headers.
- **Priority:** Must — Explicit MoSCoW Must
- **Planned implementation:** extract/format_probe.py and isolated Binwalk/tool adapters.
- **Planned verification:** Real format fixtures plus nested compression and headers.
- **Required evidence:** `evidence/extraction/format-matrix.json`
- **Execution day:** 1

## FWX-STATIC-002

- **PRD section:** §10 Week 1
- **Requirement:** Include entropy analysis in Binwalk unpacker.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** extract/entropy.py bounded-window entropy.
- **Planned verification:** Known low/high entropy regions.
- **Required evidence:** `evidence/extraction/entropy.json`
- **Execution day:** 1

## FWX-STATIC-003

- **PRD section:** §6.1 FR-1.2
- **Requirement:** Reconstruct rootfs and inventory path, type, size and hash.
- **Priority:** Must — Explicit MoSCoW Must
- **Planned implementation:** extract/rootfs.py and inventory records.
- **Planned verification:** Compare fixture expected tree and metadata.
- **Required evidence:** `evidence/extraction/inventory.json`
- **Execution day:** 1

## FWX-STATIC-004

- **PRD section:** §6.1 FR-1.3
- **Requirement:** Enumerate executables and shared libraries; detect architecture, endianness and bitness per ELF.
- **Priority:** Must — Explicit MoSCoW Must
- **Planned implementation:** static/elf.py header parser including shared objects.
- **Planned verification:** Cross-architecture/endian/word-size ELF fixtures.
- **Required evidence:** `evidence/static/elf-matrix.json`
- **Execution day:** 1

## FWX-STATIC-005

- **PRD section:** §6.1 FR-1.4; §8.1 example
- **Requirement:** Audit every ELF: NX/DEP, canaries, RELRO none/partial/full, PIE/ASLR capability, FORTIFY and stripped; persist/emit matrix.
- **Priority:** Must — Explicit MoSCoW Must
- **Planned implementation:** static/hardening.py; distinguish PIE from runtime ASLR.
- **Planned verification:** Compiler variants and checksec spot comparisons.
- **Required evidence:** `evidence/static/checksec-comparison.json`
- **Execution day:** 1

## FWX-STATIC-006

- **PRD section:** §6.1 FR-1.5
- **Requirement:** Flag banned-function usage and writable/executable segments as downstream risk leads.
- **Priority:** Should — Explicit MoSCoW Should
- **Planned implementation:** static/leads.py heuristic annotations.
- **Planned verification:** Positive/negative imports and W+X fixtures.
- **Required evidence:** `evidence/static/risk-leads.json`
- **Execution day:** 3

## FWX-EMU-001

- **PRD section:** §6.2 FR-2.1; §§2, 4.1
- **Requirement:** Containerized QEMU user-mode execution for MIPS, ARM32, ARM64 and x86_64.
- **Priority:** Must — Explicit MoSCoW Must
- **Planned implementation:** emulation/qemu_user.py with software path independent of KVM.
- **Planned verification:** Real controlled binary per target; repeat sandboxed outputs.
- **Required evidence:** `evidence/emulation/architecture-matrix.json`
- **Execution day:** 2

## FWX-EMU-002

- **PRD section:** §5.3; Appendix A
- **Requirement:** Represent MIPSEL distinctly alongside MIPS, ARM32, ARM64 and x86_64.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** Architecture enum and mipsel adapter preserve endianness.
- **Planned verification:** MIPSEL ELF/execution fixture and schema round trip.
- **Required evidence:** `evidence/emulation/mipsel.json`
- **Execution day:** 2

## FWX-EMU-003

- **PRD section:** §6.2 FR-2.2; §§4.2, 10 Week 2, 14
- **Requirement:** Best-effort full-system userland/service bring-up, NVRAM/peripheral stubs and graceful fallback; completeness not guaranteed.
- **Priority:** Should — Explicit Should; explicitly best-effort capability
- **Planned implementation:** emulation/qemu_system.py bounded TCG boot/stubs; explicit user/static/symbolic fallback.
- **Planned verification:** Supported boot fixture and peripheral/boot timeout fallback.
- **Required evidence:** `evidence/emulation/full-system.json`
- **Execution day:** 2

## FWX-EMU-004

- **PRD section:** §6.2 FR-2.3; §10 Week 2
- **Requirement:** Contained non-routed network reaching emulated HTTP/web, UPnP and MQTT services.
- **Priority:** Must — Explicit MoSCoW Must
- **Planned implementation:** sandbox/network.py job-local isolated service network.
- **Planned verification:** Local reachability for each protocol; outside packet capture.
- **Required evidence:** `evidence/containment/service-network.pcap`
- **Execution day:** 2

## FWX-EMU-005

- **PRD section:** §6.2 FR-2.4
- **Requirement:** Snapshot/restore emulated state for repeatable deterministic runs.
- **Priority:** Could — Explicit MoSCoW Could, not renamed best-effort
- **Planned implementation:** emulation/snapshots.py capability-aware snapshots.
- **Planned verification:** Restore twice and compare controlled state.
- **Required evidence:** `evidence/emulation/snapshots.json`
- **Execution day:** 5

## FWX-SYM-001

- **PRD section:** §6.3 FR-3.1; §10 Week 3
- **Requirement:** angr paths from network/CGI parameters and environment to strcpy, memcpy, sprintf, system and popen.
- **Priority:** Must — Explicit MoSCoW Must
- **Planned implementation:** analysis/sources.py, sinks.py and angr runner.
- **Planned verification:** Controlled positive/negative reachability for each source/sink model.
- **Required evidence:** `evidence/analysis/source-sink-matrix.json`
- **Execution day:** 3

## FWX-SYM-002

- **PRD section:** §6.3 FR-3.2
- **Requirement:** Track attacker-controlled data to sinks; report tainted path and reaching condition.
- **Priority:** Must — Explicit MoSCoW Must
- **Planned implementation:** analysis/taint.py provenance and redacted constraints.
- **Planned verification:** Dependent/independent input fixtures; verify condition/path.
- **Required evidence:** `evidence/analysis/taint-condition.json`
- **Execution day:** 3

## FWX-SYM-003

- **PRD section:** §6.3 FR-3.3
- **Requirement:** Diagnostic faulting address, registers, stack/heap overflow offset, call path and candidate CWE for human validation.
- **Priority:** Must — Explicit MoSCoW Must
- **Planned implementation:** analysis/crash.py artifact linked by evidence_ref.
- **Planned verification:** Known crash/noncrash fixtures; inspect every diagnostic field.
- **Required evidence:** `evidence/analysis/crash-state.json`
- **Execution day:** 3

## FWX-SYM-004

- **PRD section:** §6.3 FR-3.4; §7.2 SC-2.2; §14
- **Requirement:** Path/state/depth/time/memory budgets, pruning and merging; partial results explicitly incomplete.
- **Priority:** Must — Explicit MoSCoW Must
- **Planned implementation:** analysis/budgets.py strategies and external watchdog.
- **Planned verification:** Loop/explosion/state/depth/memory/time fixtures and merge cases.
- **Required evidence:** `evidence/analysis/budget-results.json`
- **Execution day:** 3

## FWX-FUZZ-001

- **PRD section:** §6.4 FR-4.1; §10 Week 4
- **Requirement:** Protocol-aware HTTP/UPnP/MQTT fuzzing of emulated services for crash discovery.
- **Priority:** Should — Explicit MoSCoW Should
- **Planned implementation:** fuzz/protocols adapters inside isolated service network.
- **Planned verification:** Real controlled services and crash fixtures.
- **Required evidence:** `evidence/fuzz/protocol-matrix.json`
- **Execution day:** 4

## FWX-FUZZ-002

- **PRD section:** §6.4 FR-4.2
- **Requirement:** Deterministic seeded corpora, minimized crash inputs, diagnostic reproducer and emulated crash state.
- **Priority:** Should — Explicit MoSCoW Should
- **Planned implementation:** fuzz/corpus.py and minimize.py; local diagnostic replay.
- **Planned verification:** Fixed-seed replay, minimization and artifact safety checks.
- **Required evidence:** `evidence/fuzz/replay.json`
- **Execution day:** 4

## FWX-FUZZ-003

- **PRD section:** §6.4 FR-4.3
- **Requirement:** Deduplicate crashes by stack/backtrace hash into normalized findings.
- **Priority:** Should — Explicit MoSCoW Should
- **Planned implementation:** fuzz/dedup.py and report normalizer.
- **Planned verification:** Equivalent/distinct stack fixtures and schema checks.
- **Required evidence:** `evidence/fuzz/dedup.json`
- **Execution day:** 4

## FWX-SECRET-001

- **PRD section:** §§2, 4.1, 5.1, 10 Week 3
- **Requirement:** Pattern and entropy detection of hardcoded API keys, credentials/passwords, private keys and certificates.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** scanners/secrets.py with rule provenance.
- **Planned verification:** Synthetic secrets/benign entropy fixtures; real-image evidence when found.
- **Required evidence:** `evidence/scanners/secret-detection.json`
- **Execution day:** 3

## FWX-SECRET-002

- **PRD section:** §§4.1, 5.1, 10 Week 3; Appendix B
- **Requirement:** Detect weak/deprecated crypto and hashes including security-context MD5/SHA-1.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** scanners/crypto.py context rules and calibrated confidence.
- **Planned verification:** Weak/acceptable/context-negative fixtures and real classified samples.
- **Required evidence:** `evidence/scanners/crypto-detection.json`
- **Execution day:** 3

## FWX-SAFE-001

- **PRD section:** §§1.1, 4.3; §7.1 SC-1.1
- **Requirement:** All analysis stages and execution/emulation isolated; workers have zero external egress, proven by test.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** Networked dispatcher launches no-egress one-shot analysis containers; sandbox cannot reach broker/DB.
- **Planned verification:** DNS/TCP/UDP/IPv4/IPv6/host-route attempts for every profile and outside capture.
- **Required evidence:** `evidence/containment/no-egress.json`
- **Execution day:** 2

## FWX-SAFE-002

- **PRD section:** §7.1 SC-1.2
- **Requirement:** No service or fuzzing packet escapes analysis network.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** Internal job network; deny external routing/forwarding.
- **Planned verification:** Local service access plus outside capture proving no escape.
- **Required evidence:** `evidence/containment/packet-proof.json`
- **Execution day:** 2

## FWX-SAFE-003

- **PRD section:** §7.1 SC-1.3; §14
- **Requirement:** Least privilege, restricted syscalls and denied host access.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** Nonroot, drop capabilities, read-only root, seccomp/AppArmor, restricted mounts; no job Docker socket.
- **Planned verification:** Controlled denied file/device/syscall/capability attempts.
- **Required evidence:** `evidence/containment/profile-tests.json`
- **Execution day:** 2

## FWX-SAFE-004

- **PRD section:** §4.3; §7.2 SC-2.1
- **Requirement:** Per-job CPU/memory/wall limits with termination on breach.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** cgroups plus CPU-consumed-time/wall watchdog; terminate process tree and clean resources.
- **Planned verification:** Separate CPU/memory/wall breaches and no remaining descendants.
- **Required evidence:** `evidence/containment/quota-tests.json`
- **Execution day:** 2

## FWX-SAFE-005

- **PRD section:** §7.2 SC-2.3
- **Requirement:** Concurrency and queue back-pressure prevent aggregate exhaustion; remain responsive under load.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** Bounded admissions, queue and worker slots sized for RAM.
- **Planned verification:** Controlled queue saturation, API response and resource measurements.
- **Required evidence:** `evidence/containment/backpressure.json`
- **Execution day:** 2

## FWX-SAFE-006

- **PRD section:** §4.3; §7.3 SC-3.1
- **Requirement:** Automatically redact secrets, keys, passwords, certificates and proprietary IP/strings in stored/displayed output; no plaintext secrets persisted by default.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** Central sanitizer before DB/artifacts/logs/traces/API/UI/export; restricted raw inputs.
- **Planned verification:** Search every output surface for synthetic sentinel secrets.
- **Required evidence:** `evidence/redaction/persistence-proof.json`
- **Execution day:** 3

## FWX-SAFE-007

- **PRD section:** §7.3 SC-3.2
- **Requirement:** Salted hash/fingerprint references retain actionability without secret values.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** scanners/fingerprint.py with protected salt scope.
- **Planned verification:** Salted fingerprint tests and absence of values.
- **Required evidence:** `evidence/redaction/fingerprint.json`
- **Execution day:** 3

## FWX-SAFE-008

- **PRD section:** §7.3 SC-3.3; §14
- **Requirement:** Any unredacted artifact access/reveal authorized and audited.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** Restricted artifact service; deny by default; append-only authorization/reveal events.
- **Planned verification:** Unauthorized denial and authorized controlled reveal, no value in audit.
- **Required evidence:** `evidence/redaction/reveal-authorization.json`
- **Execution day:** 3

## FWX-SAFE-009

- **PRD section:** §§10, 15
- **Requirement:** Mentor signs off isolation and quotas before untrusted binary emulation.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** Named approval tied to sandbox revision; dispatcher blocks unapproved untrusted runs.
- **Planned verification:** Missing/stale approval blocks execution; controlled fixtures only before sign-off.
- **Required evidence:** `evidence/approvals/containment-signoff.md`
- **Execution day:** 2

## FWX-OBS-001

- **PRD section:** §§4.3, 5.2
- **Requirement:** Immutable append-only audit log of every job input, parameters, artifacts and findings.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** audit/events.py append-only role/storage and artifact references.
- **Planned verification:** Deny runtime update/delete; verify lifecycle event completeness.
- **Required evidence:** `evidence/observability/audit-integrity.json`
- **Execution day:** 1

## FWX-OBS-002

- **PRD section:** §§5.2, 9, 10 Week 4, 13.2
- **Requirement:** OpenTelemetry traces every job stage and collects lifecycle metrics.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** observability/otel.py queue context; sandbox local spool exported by trusted collector.
- **Planned verification:** Check stage spans/metrics and no sensitive attributes.
- **Required evidence:** `evidence/observability/trace.json`
- **Execution day:** 4

## FWX-API-001

- **PRD section:** §8.1
- **Requirement:** POST /api/v1/firmware/upload: Ingest raw .bin/.img, return firmware ID and queue analysis.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** api/routes/upload.py and OpenAPI.
- **Planned verification:** HTTP integration against persisted fixture; response/error contract checks.
- **Required evidence:** `evidence/api/upload.json`
- **Execution day:** 1

## FWX-API-002

- **PRD section:** §8.1
- **Requirement:** GET /api/v1/firmware/{id}: Return image status and summary.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** api/routes/summary.py and OpenAPI.
- **Planned verification:** HTTP integration against persisted fixture; response/error contract checks.
- **Required evidence:** `evidence/api/summary.json`
- **Execution day:** 1

## FWX-API-003

- **PRD section:** §8.1
- **Requirement:** GET /api/v1/firmware/{id}/filesystem: Return reconstructed inventory.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** api/routes/filesystem.py and OpenAPI.
- **Planned verification:** HTTP integration against persisted fixture; response/error contract checks.
- **Required evidence:** `evidence/api/filesystem.json`
- **Execution day:** 1

## FWX-API-004

- **PRD section:** §8.1
- **Requirement:** GET /api/v1/firmware/{id}/binary-audit: Return per-ELF architecture, endianness, bits and hardening matrix.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** api/routes/binary_audit.py and OpenAPI.
- **Planned verification:** HTTP integration against persisted fixture; response/error contract checks.
- **Required evidence:** `evidence/api/binary_audit.json`
- **Execution day:** 1

## FWX-API-005

- **PRD section:** §8.1
- **Requirement:** GET /api/v1/firmware/{id}/vulnerabilities: Return CWEs, crash offsets and static findings.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** api/routes/vulnerabilities.py and OpenAPI.
- **Planned verification:** HTTP integration against persisted fixture; response/error contract checks.
- **Required evidence:** `evidence/api/vulnerabilities.json`
- **Execution day:** 4

## FWX-API-006

- **PRD section:** §8.1
- **Requirement:** GET /api/v1/firmware/{id}/report: Return normalized static/dynamic/scanner report.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** api/routes/report.py and OpenAPI.
- **Planned verification:** HTTP integration against persisted fixture; response/error contract checks.
- **Required evidence:** `evidence/api/report.json`
- **Execution day:** 4

## FWX-API-007

- **PRD section:** §8.1
- **Requirement:** GET /api/v1/jobs/{jobId}: Return job status and telemetry.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** api/routes/jobs.py and OpenAPI.
- **Planned verification:** HTTP integration against persisted fixture; response/error contract checks.
- **Required evidence:** `evidence/api/jobs.json`
- **Execution day:** 1

## FWX-UI-001

- **PRD section:** §8.2
- **Requirement:** Browse reconstructed file tree with per-file metadata and hashes.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** ui/filesystem
- **Planned verification:** Browser compares nested tree and metadata to API.
- **Required evidence:** `evidence/ui/tree.png`
- **Execution day:** 4

## FWX-UI-002

- **PRD section:** §8.2
- **Requirement:** All-ELF NX/PIE/RELRO/canary/FORTIFY table sortable by risk.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** ui/mitigations
- **Planned verification:** Browser risk sorting and all-row completeness.
- **Required evidence:** `evidence/ui/matrix.png`
- **Execution day:** 4

## FWX-UI-003

- **PRD section:** §8.2
- **Requirement:** Interactive CFG for selected binary/function supports taint-path review.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** ui/cfg with Ghidra/angr graph export
- **Planned verification:** Select function, pan/zoom and inspect real taint path.
- **Required evidence:** `evidence/ui/cfg.png`
- **Execution day:** 4

## FWX-UI-004

- **PRD section:** §8.2
- **Requirement:** Filterable findings/crash log with CWE, risk, address/offset, confidence and redacted evidence.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** ui/findings
- **Planned verification:** Browser filters and secret redaction assertions.
- **Required evidence:** `evidence/ui/findings.png`
- **Execution day:** 4

## FWX-SCHEMA-001

- **PRD section:** §5.3; Appendix A
- **Requirement:** All findings include vulnerability_id: UUID, stable finding identifier.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** schemas/finding-v1.json and domain/finding.py; normalize every producer.
- **Planned verification:** Positive/negative schema checks and real finding round trip for vulnerability_id.
- **Required evidence:** `evidence/schema/validation.json`
- **Execution day:** 3

## FWX-SCHEMA-002

- **PRD section:** §5.3; Appendix A
- **Requirement:** All findings include firmware_id: UUID.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** schemas/finding-v1.json and domain/finding.py; normalize every producer.
- **Planned verification:** Positive/negative schema checks and real finding round trip for firmware_id.
- **Required evidence:** `evidence/schema/validation.json`
- **Execution day:** 3

## FWX-SCHEMA-003

- **PRD section:** §5.3; Appendix A
- **Requirement:** All findings include binary: rootfs path string.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** schemas/finding-v1.json and domain/finding.py; normalize every producer.
- **Planned verification:** Positive/negative schema checks and real finding round trip for binary.
- **Required evidence:** `evidence/schema/validation.json`
- **Execution day:** 3

## FWX-SCHEMA-004

- **PRD section:** §5.3; Appendix A
- **Requirement:** All findings include architecture: enum ARM32, ARM64, MIPS, MIPSEL, x86_64.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** schemas/finding-v1.json and domain/finding.py; normalize every producer.
- **Planned verification:** Positive/negative schema checks and real finding round trip for architecture.
- **Required evidence:** `evidence/schema/validation.json`
- **Execution day:** 3

## FWX-SCHEMA-005

- **PRD section:** §5.3; Appendix A
- **Requirement:** All findings include category: enum memory_corruption, hardcoded_secret, weak_crypto, missing_mitigation, command_injection.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** schemas/finding-v1.json and domain/finding.py; normalize every producer.
- **Planned verification:** Positive/negative schema checks and real finding round trip for category.
- **Required evidence:** `evidence/schema/validation.json`
- **Execution day:** 3

## FWX-SCHEMA-006

- **PRD section:** §5.3; Appendix A
- **Requirement:** All findings include cwe: CWE string.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** schemas/finding-v1.json and domain/finding.py; normalize every producer.
- **Planned verification:** Positive/negative schema checks and real finding round trip for cwe.
- **Required evidence:** `evidence/schema/validation.json`
- **Execution day:** 3

## FWX-SCHEMA-007

- **PRD section:** §5.3; Appendix A
- **Requirement:** All findings include address: hex virtual-address string or null.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** schemas/finding-v1.json and domain/finding.py; normalize every producer.
- **Planned verification:** Positive/negative schema checks and real finding round trip for address.
- **Required evidence:** `evidence/schema/validation.json`
- **Execution day:** 3

## FWX-SCHEMA-008

- **PRD section:** §5.3; Appendix A
- **Requirement:** All findings include sink: string or null.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** schemas/finding-v1.json and domain/finding.py; normalize every producer.
- **Planned verification:** Positive/negative schema checks and real finding round trip for sink.
- **Required evidence:** `evidence/schema/validation.json`
- **Execution day:** 3

## FWX-SCHEMA-009

- **PRD section:** §5.3; Appendix A
- **Requirement:** All findings include source: input-origin string or null.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** schemas/finding-v1.json and domain/finding.py; normalize every producer.
- **Planned verification:** Positive/negative schema checks and real finding round trip for source.
- **Required evidence:** `evidence/schema/validation.json`
- **Execution day:** 3

## FWX-SCHEMA-010

- **PRD section:** §5.3; Appendix A
- **Requirement:** All findings include tainted_path: array of hex addresses.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** schemas/finding-v1.json and domain/finding.py; normalize every producer.
- **Planned verification:** Positive/negative schema checks and real finding round trip for tainted_path.
- **Required evidence:** `evidence/schema/validation.json`
- **Execution day:** 3

## FWX-SCHEMA-011

- **PRD section:** §5.3; Appendix A
- **Requirement:** All findings include crash_state.fault_address: hex string or null.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** schemas/finding-v1.json and domain/finding.py; normalize every producer.
- **Planned verification:** Positive/negative schema checks and real finding round trip for crash_state.fault_address.
- **Required evidence:** `evidence/schema/validation.json`
- **Execution day:** 3

## FWX-SCHEMA-012

- **PRD section:** §5.3; Appendix A
- **Requirement:** All findings include crash_state.registers: object or null.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** schemas/finding-v1.json and domain/finding.py; normalize every producer.
- **Planned verification:** Positive/negative schema checks and real finding round trip for crash_state.registers.
- **Required evidence:** `evidence/schema/validation.json`
- **Execution day:** 3

## FWX-SCHEMA-013

- **PRD section:** §5.3; Appendix A
- **Requirement:** All findings include crash_state.overflow_offset: integer or null.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** schemas/finding-v1.json and domain/finding.py; normalize every producer.
- **Planned verification:** Positive/negative schema checks and real finding round trip for crash_state.overflow_offset.
- **Required evidence:** `evidence/schema/validation.json`
- **Execution day:** 3

## FWX-SCHEMA-014

- **PRD section:** §5.3; Appendix A
- **Requirement:** All findings include crash_state.stack_hash: string or null.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** schemas/finding-v1.json and domain/finding.py; normalize every producer.
- **Planned verification:** Positive/negative schema checks and real finding round trip for crash_state.stack_hash.
- **Required evidence:** `evidence/schema/validation.json`
- **Execution day:** 3

## FWX-SCHEMA-015

- **PRD section:** §5.3; Appendix A
- **Requirement:** All findings include risk_rating: enum critical, high, medium, low, info.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** schemas/finding-v1.json and domain/finding.py; normalize every producer.
- **Planned verification:** Positive/negative schema checks and real finding round trip for risk_rating.
- **Required evidence:** `evidence/schema/validation.json`
- **Execution day:** 3

## FWX-SCHEMA-016

- **PRD section:** §5.3; Appendix A
- **Requirement:** All findings include confidence: enum confirmed, probable, heuristic.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** schemas/finding-v1.json and domain/finding.py; normalize every producer.
- **Planned verification:** Positive/negative schema checks and real finding round trip for confidence.
- **Required evidence:** `evidence/schema/validation.json`
- **Execution day:** 3

## FWX-SCHEMA-017

- **PRD section:** §5.3; Appendix A
- **Requirement:** All findings include evidence_ref: redacted artifact-reference string.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** schemas/finding-v1.json and domain/finding.py; normalize every producer.
- **Planned verification:** Positive/negative schema checks and real finding round trip for evidence_ref.
- **Required evidence:** `evidence/schema/validation.json`
- **Execution day:** 3

## FWX-SCHEMA-018

- **PRD section:** §5.3; Appendix A
- **Requirement:** All findings include redacted: boolean.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** schemas/finding-v1.json and domain/finding.py; normalize every producer.
- **Planned verification:** Positive/negative schema checks and real finding round trip for redacted.
- **Required evidence:** `evidence/schema/validation.json`
- **Execution day:** 3

## FWX-SCHEMA-019

- **PRD section:** §5.3; Appendix A
- **Requirement:** All findings include status: enum new, triaged, validated, false_positive.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** schemas/finding-v1.json and domain/finding.py; normalize every producer.
- **Planned verification:** Positive/negative schema checks and real finding round trip for status.
- **Required evidence:** `evidence/schema/validation.json`
- **Execution day:** 3

## FWX-SCHEMA-020

- **PRD section:** §5.3; Appendix A
- **Requirement:** All findings include detected_at: RFC3339 UTC string.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** schemas/finding-v1.json and domain/finding.py; normalize every producer.
- **Planned verification:** Positive/negative schema checks and real finding round trip for detected_at.
- **Required evidence:** `evidence/schema/validation.json`
- **Execution day:** 3

## FWX-SCHEMA-021

- **PRD section:** §§5.3, 11; Appendix A
- **Requirement:** Version JSON schema; uniformly normalize static, emulation, taint and scanner findings; no exploit artifacts.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** Schema registry and report serializer; extra diagnostics via evidence_ref.
- **Planned verification:** Validate every producer and real samples against versioned schema.
- **Required evidence:** `evidence/schema/real-samples.json`
- **Execution day:** 3

## FWX-SCHEMA-022

- **PRD section:** §14
- **Requirement:** Calibrated confidence, explicit heuristic labels, taint-condition evidence and dedup reduce false positives.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** reporting/classification.py, dedup.py and review rubric.
- **Planned verification:** Human review of positive/negative fixtures and real findings.
- **Required evidence:** `evidence/classification/review.md`
- **Execution day:** 3

## FWX-SCHEMA-023

- **PRD section:** Appendix B
- **Requirement:** Use reference mappings CWE-120, 121/122, 787, 134, 78, 798/259, 321, 327/328 and 1277 only where evidence supports them.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** reporting/cwe.py catalog; CWE-1277 is reference-only, not a required new update detector.
- **Planned verification:** Check mapping catalog and actual applicability; no flaw inferred from reference alone.
- **Required evidence:** `evidence/classification/cwe-mapping.json`
- **Execution day:** 3

## FWX-DELIV-001

- **PRD section:** §11
- **Requirement:** Version-controlled modular repository, clear commit history and documented PR workflow.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** Repository layout, focused commits and CONTRIBUTING.md.
- **Planned verification:** Review history and workflow.
- **Required evidence:** `evidence/delivery/repository.md`
- **Execution day:** 1

## FWX-DELIV-002

- **PRD section:** §11
- **Requirement:** README/runbook cover API/workers/Postgres/Redis/sandbox deployment, image submission, results and teardown.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** README.md and docs/runbook.md reproducible commands.
- **Planned verification:** New engineer performs clean setup/run/teardown.
- **Required evidence:** `evidence/delivery/reproduction.md`
- **Execution day:** 5

## FWX-DELIV-003

- **PRD section:** §11
- **Requirement:** Architecture document/diagram cover components, communication, data and containment; match code.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** docs/architecture.md and boundary diagram.
- **Planned verification:** Review against deployed services/dataflow.
- **Required evidence:** `evidence/delivery/architecture-review.md`
- **Execution day:** 5

## FWX-DELIV-004

- **PRD section:** §11
- **Requirement:** Working unpacker, static audit, emulation, symbolic/taint and secret/crypto pipeline.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** All stage modules integrated.
- **Planned verification:** Real-image vertical slice with all stage artifacts.
- **Required evidence:** `evidence/e2e/stages.json`
- **Execution day:** 4

## FWX-DELIV-005

- **PRD section:** §11
- **Requirement:** Versioned finding schema and real-image sample findings.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** schemas/finding-v1.json and sanitized samples.
- **Planned verification:** Validate provenance and schema.
- **Required evidence:** `evidence/schema/real-samples.json`
- **Execution day:** 5

## FWX-DELIV-006

- **PRD section:** §11
- **Requirement:** Mitigation matrix for an analyzed open-source image.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** Persist/report matrix and image hash.
- **Planned verification:** ELF completeness and checksec spot comparisons.
- **Required evidence:** `evidence/static/real-image-matrix.json`
- **Execution day:** 5

## FWX-DELIV-007

- **PRD section:** §11
- **Requirement:** Dashboard and documented REST/gRPC endpoints with example requests/responses.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** REST chosen from alternatives; OpenAPI/UI docs.
- **Planned verification:** Execute examples and inspect required views.
- **Required evidence:** `evidence/api/examples.json`
- **Execution day:** 4

## FWX-DELIV-008

- **PRD section:** §11
- **Requirement:** Sandbox profiles, egress-deny configuration, quota enforcement and tests.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** infra/sandbox and tests/containment.
- **Planned verification:** Real controlled denial/quota tests.
- **Required evidence:** `evidence/containment/profile-tests.json`
- **Execution day:** 2

## FWX-DELIV-009

- **PRD section:** §11
- **Requirement:** Final write-up: results, decisions, trade-offs and explicit known limitations.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** docs/final-writeup.md and known-limitations.md.
- **Planned verification:** Cross-check claims with evidence/traceability.
- **Required evidence:** `evidence/delivery/writeup-review.md`
- **Execution day:** 5

## FWX-TEST-001

- **PRD section:** §11; §§12, 13.2
- **Requirement:** Automated unpacking/static/emulation/analysis/redaction tests and core-module coverage report.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** tests/unit, integration, containment, e2e and coverage configuration.
- **Planned verification:** Run real integration and suitable units; save exits/coverage; no invented threshold.
- **Required evidence:** `evidence/tests/coverage.xml`
- **Execution day:** 5

## FWX-EVID-001

- **PRD section:** §12
- **Requirement:** Repository URL/history and README/runbook.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** Evidence index with repository/exact revision.
- **Planned verification:** Verify reference and commit.
- **Required evidence:** `evidence/delivery/repository.md`
- **Execution day:** 5

## FWX-EVID-002

- **PRD section:** §12
- **Requirement:** Architecture diagram matching delivered code.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** Export versioned diagram.
- **Planned verification:** Reviewer checks deployed architecture.
- **Required evidence:** `evidence/delivery/architecture.svg`
- **Execution day:** 5

## FWX-EVID-003

- **PRD section:** §12
- **Requirement:** Named open-source image unpack, file tree and per-binary hardening table.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** Capture image name/license/hash and stage outputs.
- **Planned verification:** Verify provenance and artifact hashes.
- **Required evidence:** `evidence/extraction/real-image.json`
- **Execution day:** 5

## FWX-EVID-004

- **PRD section:** §12
- **Requirement:** Real JSON taint-to-sink finding with crash state/CWE and redacted secret/crypto finding.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** Collect sanitized real-image artifacts; synthetic fixtures cannot substitute.
- **Planned verification:** Validate provenance/schema and actual analysis.
- **Required evidence:** `evidence/findings/real-samples.json`
- **Execution day:** 5

## FWX-EVID-005

- **PRD section:** §12
- **Requirement:** Screen recording from API upload to dashboard report.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** Record completed real-image run and job IDs.
- **Planned verification:** Replay and correlate artifacts.
- **Required evidence:** `evidence/e2e/demo.webm`
- **Execution day:** 5

## FWX-EVID-006

- **PRD section:** §12
- **Requirement:** No-egress and quota-breach termination proof.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** Controlled test evidence for exact profile used on real image.
- **Planned verification:** Inspect attempted traffic, denial and termination.
- **Required evidence:** `evidence/containment/proof.json`
- **Execution day:** 5

## FWX-EVID-007

- **PRD section:** §12
- **Requirement:** Proof discovered secret stored only as fingerprint.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** Sanitized store scan and fingerprint artifact.
- **Planned verification:** Verify no plaintext in output stores.
- **Required evidence:** `evidence/redaction/persistence-proof.json`
- **Execution day:** 5

## FWX-EVID-008

- **PRD section:** §12
- **Requirement:** Static audit plus basic-symbolic throughput measurement on representative image.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** Time exact stages; record hardware/image/config.
- **Planned verification:** Recompute elapsed time from start/end.
- **Required evidence:** `evidence/performance/benchmark.json`
- **Execution day:** 5

## FWX-EVID-009

- **PRD section:** §12
- **Requirement:** Core-module coverage report.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** Save coverage, test command and exit.
- **Planned verification:** Inspect report tied to tested revision.
- **Required evidence:** `evidence/tests/coverage.xml`
- **Execution day:** 5

## FWX-KPI-001

- **PRD section:** §13.1
- **Requirement:** Extraction success strictly >90% of defined standard open-source IoT firmware set.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** Freeze manifest/success rule before measuring; retain failures in denominator.
- **Planned verification:** Measure successful/total >0.90, never rounded >=90%.
- **Required evidence:** `evidence/acceptance/extraction-rate.json`
- **Execution day:** 5

## FWX-KPI-002

- **PRD section:** §13.1
- **Requirement:** Static audit plus basic symbolic trace strictly <30 minutes per representative image.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** Benchmark designated image and declared stages/config.
- **Planned verification:** Wall time <1800 seconds; static-only measurement insufficient.
- **Required evidence:** `evidence/performance/benchmark.json`
- **Execution day:** 5

## FWX-KPI-003

- **PRD section:** §13.1
- **Requirement:** 100% containment reliability: every analysis job sandboxed, quotas enforced, no egress/escape.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** Enforced dispatcher/sandbox contract and audit coverage.
- **Planned verification:** Review all profiles; denial/quota suite; record denominator/failures.
- **Required evidence:** `evidence/acceptance/containment.json`
- **Execution day:** 5

## FWX-KPI-004

- **PRD section:** §13.1
- **Requirement:** Spot-checked findings have correct CWE and calibrated confidence.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** Classification rubric and reviewer sample manifest.
- **Planned verification:** Review actual evidence and confidence justification.
- **Required evidence:** `evidence/classification/review.md`
- **Execution day:** 5

## FWX-KPI-005

- **PRD section:** §13.1
- **Requirement:** 100% redaction coverage: no raw secret persisted as plaintext output.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** Central sanitizer on all output paths.
- **Planned verification:** Search sentinels across DB/logs/traces/artifacts/exports.
- **Required evidence:** `evidence/redaction/persistence-proof.json`
- **Execution day:** 5

## FWX-DOD-001

- **PRD section:** §13.2
- **Requirement:** E2E upload to CWE report on standard open-source image, viewable in dashboard.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** Release gate aggregates underlying evidence.
- **Planned verification:** Review actual linked evidence against exact condition.
- **Required evidence:** `evidence/e2e/demo.webm`
- **Execution day:** 5

## FWX-DOD-002

- **PRD section:** §13.2
- **Requirement:** Unpack >90% of standard open-source set.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** Release gate aggregates underlying evidence.
- **Planned verification:** Review actual linked evidence against exact condition.
- **Required evidence:** `evidence/acceptance/extraction-rate.json`
- **Execution day:** 5

## FWX-DOD-003

- **PRD section:** §13.2
- **Requirement:** All execution/emulation sandboxed; zero worker egress proven.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** Release gate aggregates underlying evidence.
- **Planned verification:** Review actual linked evidence against exact condition.
- **Required evidence:** `evidence/containment/no-egress.json`
- **Execution day:** 5

## FWX-DOD-004

- **PRD section:** §13.2
- **Requirement:** CPU/memory/time quotas enforced; breaching job terminated, proven.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** Release gate aggregates underlying evidence.
- **Planned verification:** Review actual linked evidence against exact condition.
- **Required evidence:** `evidence/containment/quota-tests.json`
- **Execution day:** 5

## FWX-DOD-005

- **PRD section:** §13.2
- **Requirement:** Normalized findings correctly CWE-classified with confidence.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** Release gate aggregates underlying evidence.
- **Planned verification:** Review actual linked evidence against exact condition.
- **Required evidence:** `evidence/classification/review.md`
- **Execution day:** 5

## FWX-DOD-006

- **PRD section:** §13.2
- **Requirement:** Secrets redacted and fingerprint-only by default.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** Release gate aggregates underlying evidence.
- **Planned verification:** Review actual linked evidence against exact condition.
- **Required evidence:** `evidence/redaction/persistence-proof.json`
- **Execution day:** 5

## FWX-DOD-007

- **PRD section:** §13.2
- **Requirement:** Static audit plus basic symbolic trace under 30 minutes.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** Release gate aggregates underlying evidence.
- **Planned verification:** Review actual linked evidence against exact condition.
- **Required evidence:** `evidence/performance/benchmark.json`
- **Execution day:** 5

## FWX-DOD-008

- **PRD section:** §13.2
- **Requirement:** Required API/dashboard views and OpenTelemetry job tracing.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** Release gate aggregates underlying evidence.
- **Planned verification:** Review actual linked evidence against exact condition.
- **Required evidence:** `evidence/acceptance/api-ui-otel.json`
- **Execution day:** 5

## FWX-DOD-009

- **PRD section:** §13.2
- **Requirement:** Tested/documented code; new engineer reproduces run from runbook.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** Release gate aggregates underlying evidence.
- **Planned verification:** Review actual linked evidence against exact condition.
- **Required evidence:** `evidence/delivery/reproduction.md`
- **Execution day:** 5

## FWX-GOV-001

- **PRD section:** §15
- **Requirement:** Daily written yesterday/today/blockers stand-up.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** docs/progress.md dated entries.
- **Planned verification:** Review daily execution record.
- **Required evidence:** `evidence/reviews/daily.md`
- **Execution day:** 1

## FWX-GOV-002

- **PRD section:** §15
- **Requirement:** Weekly demo/review working increment against exit criteria.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** Compressed plan retains all four original weekly exit gates as milestone demos.
- **Planned verification:** Record review and each criterion outcome.
- **Required evidence:** `evidence/reviews/milestones.md`
- **Execution day:** 5

## FWX-GOV-003

- **PRD section:** §15
- **Requirement:** All changes land via PR; sandbox, quota and redaction code receive extra scrutiny.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** CONTRIBUTING.md and review checklists.
- **Planned verification:** Check PR history and named sensitive-code reviews.
- **Required evidence:** `evidence/reviews/pr-index.md`
- **Execution day:** 1

## FWX-GOV-004

- **PRD section:** §15
- **Requirement:** Book mentor pairing early on unpacking edge cases and symbolic budgets.
- **Priority:** Must — Required prose; inferred Must, not explicit MoSCoW
- **Planned implementation:** Day 1 unpacking and pre-Day 3 budget sessions.
- **Planned verification:** Record scheduling/completion; no unsolicited messages sent.
- **Required evidence:** `evidence/reviews/pairing.md`
- **Execution day:** 1
