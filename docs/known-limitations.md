# Current known limitations

Current submission — 2026-11-10: **159 unit tests passed; selected OpenWrt checks complete.** Static plus selected analysis: **4.209340868 seconds**. Requirement ledger: **105 PASS / 7 FAIL**. Real-image crash validation and independent clean-machine reproduction remain open. See `docs/submission-2026-11-10.md` for evidence and reproduction.

## Historical assessment

Earlier milestone counts and partial-status statements below are retained as history; use the current submission record and ledger.

Superseding ledger update — 2026-11-08: **95 PASS / 17 FAIL**; 150 unit tests pass. The limitations below remain active.

2026-11-07 superseding update: local mentor authorization permits bounded real-image startup/symbolic sampling. Controlled fuzzing/replay/dedup and ARM snapshot restore now pass dedicated and full-pipeline tests. Latest unit suite: 128 passes, 35.94% whole-package unit coverage (integration execution excluded). Frozen OpenWrt extraction/static results: 6/6. Current ledger: 87 PASS / 25 FAIL. Older milestone text below is retained as history; current limitations and unmet acceptance obligations are in release-readiness.md.

Task 5 implements the controlled integrated pipeline, authenticated API, dashboard and local OpenTelemetry analysis-stage records. See task5-review.md for evidence. The full PRD remains unfinished.

- Arbitrary/untrusted firmware execution is blocked until mentor containment/quota sign-off. Exact image hashes authorize only controlled fixtures. User approval is required before external GitHub publication; PR review remains pending.
- FWX-FUZZ-001–003 remain DEFERRED per user instruction: service probes do not implement protocol fuzzing, crash minimization/replay or stack dedup. These Should requirements remain on the execution plan.
- Lifecycle tracing now covers 11 linked stages/spans and controller failure/recovery paths. Abruptly killed processes cannot export unfinished internal spans; controller telemetry records their failure.
- Current pipeline/controller/API boundaries filter unreviewed text and keys. Historical metadata/output cleanup and adversarial API/storage/export checks pass; originals remain in restricted controller quarantine. Typed numeric/hash/address metadata and user-entered labels are intentionally retained. This output contract and fixture checks do not prove a universal 100% redaction KPI.
- Symbolic analysis is bounded, with read/recv/getenv source models. Stack object inference requires the tested x86_64 DWARF/frame-pointer layout. Missing bounds/models produce heuristic or incomplete results. Raw reveal remains disabled.
- Static banned-symbol findings are low-risk heuristic leads, not proof of invocation or overflow. Absence of mitigation is reported as posture metadata, without inventing a specific CWE. Stripped/static symbols can obscure canary/FORTIFY checks; PIE indicates capability, not runtime ASLR.
- CFGFast output is bounded to 128 functions and 256 nodes/512 edges per function; it is not complete disassembly. UI graph data is available for registered symbolic targets.
- Scanner limits: 16 MiB per file, 64 MiB aggregate; ambiguous-architecture non-ELF files are skipped and reported incomplete. Pattern/entropy matches are candidates requiring review.
- Full-system controlled ARM boot/minimal NVRAM tests do not prove vendor Linux boot or full hardware models. Private-loopback service networking does not emulate every NIC/multicast/peripheral setup. No /dev/kvm; software QEMU is supported.
- Custom headers depend on recognizable embedded signatures. Extraction bounds and unsupported vendor encodings may fail or return partial results. SquashFS special inodes are metadata, not materialized devices.
- Frozen OpenWrt corpus static results from Task 2 are 6/6 generic/virtual targets; final reviewer agreement and integrated real-image acceptance remain pending. No general >90% claim outside that denominator.
- The completion regression records 85 unit passes and 32.81% whole-package unit coverage, a controlled recording, persistence failure testing and all 112 PASS/FAIL rows. Real-image symbolic throughput, complete real-image recording and independent clean-machine reproduction remain blocked/unverified. Current browser test references this machine's bundled Playwright installation; portability needs final validation.
- Docker default seccomp/AppArmor is inherited. The new bounded executable /guest tmpfs and all sandbox/quota/redaction changes require sensitive-code review. Tested route denials/quotas do not prove absence of all possible future escape paths.

Task 6 found and corrected the extraction/report file-limit interaction and transactional persistence failure handling. See task6-review.md for fresh 6/6 corpus, 42 symbolic, 36 emulation and quota/guard evidence. Final acceptance is NOT complete: 78 PASS / 34 FAIL in the conservative ledger.

Controlled cross-architecture E2E gap closed: five full production uploads passed with actual dashboard exports (docs/cross-architecture-e2e.md). This supersedes component-only coverage for ARM32/ARM64/MIPS/MIPSEL; vendor boot, real-image dynamic acceptance, calibration and human gates remain open.
