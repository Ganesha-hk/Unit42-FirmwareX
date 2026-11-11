# FirmwareX implementation plan

Planning milestone: 2026-10-19. **No application implementation or application tests have run.** Canonical scope is `../REQUIREMENTS.md`; gaps in the original plan are documented in `requirements-gap-analysis.md`. This schedule compresses the PRD's four weeks into five execution days, not a reduced feature set. Dates begin only when implementation is authorized. Every Must remains a release condition; incomplete work remains visible and blocks completion.

## Proposed repository architecture

```text
firmwarex/
├── PRD.docx, AGENTS.md, REQUIREMENTS.md, TASKS.md, ACCEPTANCE.md
├── README.md, CONTRIBUTING.md, pyproject.toml
├── locks/                       # separate control/analysis hash-locked dependencies
├── compose.yaml
├── infra/
│   ├── images/{control,extract,analysis,qemu,ghidra}/
│   ├── sandbox/                 # seccomp/AppArmor, quota/network profiles
│   └── observability/           # collector configuration
├── src/firmwarex/
│   ├── api/routes/              # seven /api/v1 routes, OpenAPI
│   ├── domain/                  # firmware, binary, finding, job contracts
│   ├── db/                      # PostgreSQL models/repositories
│   ├── pipeline/                # DAG/states, Celery tasks, admission/back-pressure
│   ├── storage/                 # restricted raw artifacts, sanitized outputs
│   ├── extract/                 # Binwalk, format helpers, rootfs, inventory, entropy
│   ├── static/                  # ELF metadata, hardening, risk leads
│   ├── sandbox/                 # trusted launcher, quotas, contained networking
│   ├── emulation/               # QEMU user/system, Unicorn, optional snapshots
│   ├── analysis/                # angr sources/sinks/taint/budgets/crash diagnostics
│   ├── scanners/                # secret/crypto, fingerprints and sanitization
│   ├── reporting/               # normalization, CWE/confidence, dedup/reports
│   ├── cfg/                     # Ghidra/angr graph adapters
│   ├── fuzz/                    # seeded HTTP/UPnP/MQTT, minimization/replay
│   ├── audit/                   # append-only events and reveal authorization
│   └── observability/           # OpenTelemetry spans/metrics
├── schemas/finding-v1.json
├── migrations/
├── ui/                          # small TypeScript/Vite UI, Cytoscape CFG
├── tests/{unit,integration,containment,e2e}/
├── fixtures/{sources,manifests}/ # controlled source fixtures, licensed-image metadata
├── scripts/                     # build/verify/demo helpers
├── docs/                        # decisions, architecture, runbook, progress, validation
└── evidence/                    # sanitized, provenance-linked real run outputs
```

Paths under src are proposals; no scaffolding is being created in this milestone. Keep large firmware images/rootfs trees, databases, environments, caches and raw secrets out of Git. Store input hashes and authorized provenance in manifests; storage lives in restricted volumes.

## Control and data boundaries

FastAPI owns upload/status/report APIs. PostgreSQL stores firmware, inventory, binary audit, job, normalized findings and artifact metadata. Redis/Celery coordinate trusted dispatch. A trusted launcher consumes work and starts one-shot analysis containers; untrusted analysis processes never receive the Docker socket, broker/database access or external network routes.

Input artifacts are read-only within each job. Bounded scratch/output mounts are per job; outputs pass through validation/redaction before becoming normal persisted results. The trusted collector harvests local trace/audit spools after execution. All extraction and static tools also run under isolation: malformed files can attack parsers even without emulation.

Network-free jobs use no network. Emulated services and protocol harnesses share only a job-local non-routed network. Validate host, IPv4/IPv6, DNS and forwarding denial, rather than treating an “internal” bridge label as proof. A networked Celery dispatcher is not an analysis sandbox and must never execute firmware itself.

Use unprivileged processes, dropped capabilities, restricted syscalls/mounts/devices and read-only roots. cgroup CPU throttling alone is not CPU-budget termination: add consumed CPU-time/wall watchdogs, kill the entire process tree, and verify cleanup. Aggregate admission/back-pressure keeps one heavy job from starving the API.

Appendix A remains the external finding contract. Reaching conditions, call paths and additional sanitized diagnostic state live in evidence artifacts referenced by evidence_ref. Explicit partial/unsupported/error stage states prevent unsupported firmware from appearing successful. Risk/confidence calibration and finding dedup are evidence-based.

## Runtime and dependency strategy

Select **CPython 3.12 in isolated Linux x86_64 containers** for control and analysis, with separate dependency locks/environments. Never replace /usr/bin/python3, change system alternatives, use sudo pip, or install the analysis stack into Python 3.14. A local developer environment, if needed, uses a separately installed 3.12 plus venv.

Current PyPI metadata inspected directly on 2026-10-19 (saved in `evidence/planning/dependency-metadata.json`) gives an initial candidate **angr 10.0.4.post1**, Python >=3.12, with a CPython 3.12 ABI3 manylinux x86_64 wheel. Its declared dependencies include archinfo/cle/pyvex 10.0.4, capstone 5.0.9, z3-solver 5.1.0.0 and optional Unicorn 2.1.4. Do not force unrelated latest claripy or mix angr-family release generations. Resolve from the chosen release metadata.

This is a metadata-supported candidate, **not an installed or tested lock**. Day 1 must resolve the entire transitive graph, confirm compatible wheels/native libraries, import engines and run tiny controlled load/CFG/solver/Unicorn cases. Pin the successful complete graph with hashes. If a candidate fails, record the failure, choose a supported matched release set and repeat; never silently relax requirements. Keep a fallback version decision explicit.

Use a digest-pinned Python 3.12 Debian-based image; select exact patch/digest at build time and record it. Control lock: FastAPI, Pydantic, SQLAlchemy/Alembic, psycopg, Celery, Redis client and OpenTelemetry. Analysis lock: chosen angr family, pyelftools, scanner dependencies and Unicorn. Separate environments avoid telemetry/API dependencies perturbing native analysis packages. Use no optional LLM/MCP extras.

Binwalk v3 is a Rust CLI: pin a release/commit and Cargo lock in a separate extraction image, plus format-specific tools (SquashFS, CramFS, UBIFS/UBI, JFFS2, cpio and ext). A Binwalk binary alone is not proof that every extraction format works. Ghidra is a separate headless CLI image with its release-matched JDK (current upstream guidance says JDK 25); avoid assuming an older Java requirement. Pin archives/checksums and tool versions. QEMU user/system executables and checksec are separate pinned native tool dependencies. C/C++ is used only for necessary native integration and controlled cross-compiled fixtures.

PostgreSQL/Redis/collector images use pinned supported releases and digests selected during implementation. Vite/TypeScript/Cytoscape frontend uses a pinned supported Node runtime and package lock; no UI framework is mandated by the PRD. Docker Compose suffices for the current single VM; Kubernetes adds no required capability here. QEMU TCG is baseline, KVM optional and currently unavailable.

Build/install dependencies in a networked build phase; runtime analysis remains offline. Record image digests, OS packages, compiler/tool versions, dependency hashes and source fixture recipes. Test a clean rebuild before calling deployment reproducible.

Primary sources checked:
- [angr package metadata](https://pypi.org/project/angr/) and [official installation guidance](https://docs.angr.io/en/v9.2.173/getting-started/installing.html). The older guide's Python minimum is version-specific; current package metadata controls the selected release.
- [Binwalk upstream](https://github.com/ReFirmLabs/binwalk/blob/master/README.md).
- [Ghidra upstream](https://github.com/NationalSecurityAgency/ghidra).
- [QEMU TCG emulation](https://www.qemu.org/docs/master/about/emulation.html).

## Five-day execution sequence

### Day 1 — Reproducible foundation and static slice

1. Establish branch/PR workflow and identity/remote configuration with the repository owner; retain supplied untracked files. Add modular scaffolding, .gitignore, dependency manifests and clean-build instructions only after this planning stop.
2. Resolve/pin isolated Python/native dependencies and perform controlled compatibility smoke tests. Reserve host RAM for the control plane; start with one heavy analysis slot.
3. Build Compose control services, migrations, typed finding/job/artifact contracts, upload SHA-256 identity and persistent job lifecycle. Introduce append-only auditing from the outset.
4. Create sandboxed extractor/static worker profile before processing firmware; verify parser resource/path restrictions using controlled fixtures. Implement Binwalk/entropy and all six filesystem families, multistage compression and vendor-header handling.
5. Reconstruct inventory and enumerate executable/shared-library ELFs; produce all hardening fields and compare to checksec.
6. Implement upload/summary/filesystem/binary-audit/job routes, collect actual evidence, and document every unsupported case.
7. Select permitted corpus and representative image, record licenses/checksums and freeze denominator/success rules. Arrange early mentor unpacking review.

Gate: original Week 1 upload → tree → matrix demonstration, checksec correctness and >90% unpack on the frozen standard corpus. Deterministic fixture coverage supplements but does not replace this corpus KPI. Failure to meet the gate remains an explicit blocker; subsequent controlled development can proceed without calling the milestone accepted.

### Day 2 — Containment and cross-architecture emulation

Finish syscall/host-denial profiles, CPU/memory/wall termination, queue back-pressure and cleanup. Run controlled no-egress, packet containment and saturation tests. Build QEMU user-mode adapters for MIPS/MIPSEL/ARM32/ARM64/x86_64 and job-local HTTP/UPnP/MQTT service networking. Attempt bounded full-system boot/stubs/fallback (Should). Record reproducibility and resource evidence.

**Human gate:** mentor reviews exact isolation/quota profile and signs off before any untrusted firmware emulation. Controlled fixtures are permitted by AGENTS.md before this gate. If sign-off is pending, continue controlled work only.

Gate: original Week 2 reproducible target execution, service-network capability, proven no-egress and quota termination. Software TCG must work without /dev/kvm.

### Day 3 — Real bounded analysis, schema and secret handling

Implement source/sink models, taint paths/reaching conditions, diagnostic crash fields and CWE classification. Enforce all budgets including state/depth/memory/time, pruning and merging, with honest incomplete status. Implement secret/crypto rules, salted fingerprints, central redaction, authorized/audited artifact access, schema normalization and confidence/dedup. Add static banned-function/W+X leads (Should). Conduct mentor budget pairing and sensitive-code review.

Gate: original Week 3 controlled real analysis results with schema-correct CWE/confidence, crash evidence and plaintext-absence proof. No fabricated findings. Real-image samples are still required for final evidence.

### Day 4 — Integration, UI and observability

Join pipeline with durable status/failure handling; finish all seven routes, four interactive dashboard views and OpenTelemetry traces/metrics. Add Should fuzzing work for HTTP/UPnP/MQTT, seeded corpora, crash minimization/replay and dedup; record unmet Should items rather than silently removing them. Validate a complete controlled-image run. After mentor sign-off only, run permitted firmware through untrusted emulation.

Gate: complete pipeline visible through API/dashboard, correlated telemetry and append-only audit; redaction enforced throughout every presentation/export path. Begin real-image evidence collection early enough to discover gaps.

### Day 5 — Acceptance, reproducibility and review

Run frozen corpus and representative-image benchmark; validate >90% extraction, <1800-second static+basic-symbolic time, 100% tested containment and redaction. Collect real-image taint/crash/CWE and secret/crypto samples, coverage, API examples and screen recording. Re-run relevant tests after fixes; inspect provenance and artifact sanitization. Finish architecture/diagram, README/runbook/teardown, decisions/trade-offs and limitations. New engineer/reviewer reproduces a run. Review all original week gates and PRs; finalize requirement-by-requirement PASS/FAIL evidence matrix.

Snapshot/restore (Could) may be attempted only after required gates; preserve deferred status. Do not declare completion if any Must is unimplemented, unverified or failed. The five-day target may slip; preserve the spec and report actual results.

## Full requirement-to-day allocation

Day here is the principal implementation/delivery day, not a claim that verification occurs only once. Every record appears exactly once; release evidence is checked on Day 5 regardless of implementation day.

| Day | Requirement IDs |
| --- | --- |
| 1 | FWX-SCOPE-001, FWX-SCOPE-002, FWX-SCOPE-003, FWX-SCOPE-004, FWX-SCOPE-005, FWX-ARCH-001, FWX-ARCH-002, FWX-ARCH-003, FWX-STATIC-001, FWX-STATIC-002, FWX-STATIC-003, FWX-STATIC-004, FWX-STATIC-005, FWX-OBS-001, FWX-API-001, FWX-API-002, FWX-API-003, FWX-API-004, FWX-API-007, FWX-DELIV-001, FWX-GOV-001, FWX-GOV-003, FWX-GOV-004 |
| 2 | FWX-ARCH-004, FWX-EMU-001, FWX-EMU-002, FWX-EMU-003, FWX-EMU-004, FWX-SAFE-001, FWX-SAFE-002, FWX-SAFE-003, FWX-SAFE-004, FWX-SAFE-005, FWX-SAFE-009, FWX-DELIV-008 |
| 3 | FWX-STATIC-006, FWX-SYM-001, FWX-SYM-002, FWX-SYM-003, FWX-SYM-004, FWX-SECRET-001, FWX-SECRET-002, FWX-SAFE-006, FWX-SAFE-007, FWX-SAFE-008, FWX-SCHEMA-001, FWX-SCHEMA-002, FWX-SCHEMA-003, FWX-SCHEMA-004, FWX-SCHEMA-005, FWX-SCHEMA-006, FWX-SCHEMA-007, FWX-SCHEMA-008, FWX-SCHEMA-009, FWX-SCHEMA-010, FWX-SCHEMA-011, FWX-SCHEMA-012, FWX-SCHEMA-013, FWX-SCHEMA-014, FWX-SCHEMA-015, FWX-SCHEMA-016, FWX-SCHEMA-017, FWX-SCHEMA-018, FWX-SCHEMA-019, FWX-SCHEMA-020, FWX-SCHEMA-021, FWX-SCHEMA-022, FWX-SCHEMA-023 |
| 4 | FWX-FUNC-001, FWX-FUZZ-001, FWX-FUZZ-002, FWX-FUZZ-003, FWX-OBS-002, FWX-API-005, FWX-API-006, FWX-UI-001, FWX-UI-002, FWX-UI-003, FWX-UI-004, FWX-DELIV-004, FWX-DELIV-007 |
| 5 | FWX-EMU-005, FWX-DELIV-002, FWX-DELIV-003, FWX-DELIV-005, FWX-DELIV-006, FWX-DELIV-009, FWX-TEST-001, FWX-EVID-001, FWX-EVID-002, FWX-EVID-003, FWX-EVID-004, FWX-EVID-005, FWX-EVID-006, FWX-EVID-007, FWX-EVID-008, FWX-EVID-009, FWX-KPI-001, FWX-KPI-002, FWX-KPI-003, FWX-KPI-004, FWX-KPI-005, FWX-DOD-001, FWX-DOD-002, FWX-DOD-003, FWX-DOD-004, FWX-DOD-005, FWX-DOD-006, FWX-DOD-007, FWX-DOD-008, FWX-DOD-009, FWX-GOV-002 |

## Human decisions and sign-off

- **Mandatory safety approval:** mentor isolation/quota sign-off before untrusted emulation (FWX-SAFE-009). Planning authorization is not this sign-off. Record reviewer/date/profile revision and attached test evidence.
- **Mandatory review workflow:** all changes land through PR; sandbox/quota/redaction changes need extra scrutiny (FWX-GOV-003). This checkout has no commits or configured Git identity observed; no PR or review is claimed.
- **Mandatory authorization on reveal:** every unredacted artifact access must be authorized and logged (FWX-SAFE-008), with ordinary outputs remaining fingerprint-only.
- **Human validation/review:** diagnostic candidates require human validation; classification/confidence spot checks, incremental demos and reproducible final acceptance need reviewer evidence (FWX-SYM-003, FWX-KPI-004, FWX-GOV-002, FWX-DOD-009).
- **Planning decisions, not extra PRD gates:** name mentor/reviewer; agree on corpus/representative image and concrete budgets; schedule pairing. No outbound messages or public upload are authorized by this document.

## Major technical risks

| Risk | Consequence | Planned response |
| --- | --- | --- |
| Five days vs original four-week brief | All Must items may not finish | Prioritize dependency/safety/static spine; retain remaining failures and extend schedule instead of downgrading scope. |
| Python/native dependency drift | Import/ABI/solver failures | Isolated 3.12, matched release set, clean build and controlled smoke gate; separate native tools. |
| 7.2 GiB RAM and no KVM | Slow boot/path exploration; OOM; benchmark failure | Single heavy job, explicit quotas, TCG baseline, bounded analysis; measure rather than promise <30 minutes. |
| Extraction diversity/custom headers | >90% KPI may fail | Freeze representative corpus early; real per-format fixtures; explicit unsupported outcomes. |
| Peripheral/NVRAM dependencies | Full-system boot unavailable | Best-effort stub profiles, user-mode/static/symbolic fallback; never fake boot success. |
| Meaningful taint and state merging | False positives or missed paths | Controlled source/sink tests, evidence-based conditions, merge correctness and partial status. |
| Real-image sample availability | Required evidence missing despite fixture success | Select licensed images early; preserve unmet evidence gate instead of inventing findings. |
| Network/control-plane boundary | Broker access creates forbidden egress | Separate dispatcher and sandbox, local artifact handoff, packet denial tests. |
| Plaintext leakage/audit mutation | Safety/acceptance failure | Central sanitizer, authorized reveal, append-only roles, full output-surface sentinel checks. |
| Missing mentor/reviewer | Untrusted emulation/release blocked | Continue controlled fixtures and docs; obtain named review before crossing gate. |

## Verification discipline

Tests are future plans. Save real commands, exit codes, revision, image/config hashes and sanitized outputs under evidence/. Missing evidence means NOT STARTED/UNVERIFIED, never PASS. Requirements without prescribed numerical thresholds (e.g. coverage and queue responsiveness) must not acquire invented PRD thresholds; choose and document engineering criteria separately.

The source specification uses absolute safety language. Test results can demonstrate the defined profiles/cases, not mathematically guarantee all possible hostile inputs. Record tested scope and limitations candidly.
