# PRD comparison with original task and acceptance plans

Compared before modification on 2026-10-19. The original plans named many capabilities but did not enumerate all required behavior. “Missing” below means absent or insufficiently explicit, not that the existing plan contradicts the PRD. Original user content is retained; additive checklists in TASKS.md and ACCEPTANCE.md now reference every extracted ID.

| PRD obligation | Original TASKS.md gap | Original ACCEPTANCE.md gap | Requirement IDs |
| --- | --- | --- | --- |
| Complete extraction scope | “Common filesystem handling” did not name cpio/ext, nested compression/custom headers or entropy | No format matrix | FWX-STATIC-001, FWX-STATIC-002 |
| Inventory/ELF exact contract | Missing inventory path/type/size/hash and explicit shared-library enumeration | Generic inventory evidence only | FWX-STATIC-003, FWX-STATIC-004 |
| Hardening semantics | RELRO states and distinction between PIE and runtime ASLR not explicit | Generic checksec evidence | FWX-STATIC-005 |
| Static risk leads (Should) | Banned functions and W+X segments absent | Absent | FWX-STATIC-006 |
| Full-system stubs/fallback (Should, best-effort) | Generic support, no NVRAM/peripheral stub criteria | Absent | FWX-EMU-003 |
| Contained service network (Must) | Qualified “where applicable”; PRD requires network capability for HTTP/UPnP/MQTT | No protocol/packet containment checks | FWX-EMU-004, FWX-SAFE-002 |
| Snapshot/restore (Could) | Absent | Absent; optional status must stay visible | FWX-EMU-005 |
| Symbolic source and diagnostic detail | Network/CGI/environment, fault/register/stack-heap-offset/call-path not explicit | Generic sample/crash evidence | FWX-SYM-001–003 |
| Symbolic bounds | Missing depth budget and state merging | No independent budget/incomplete checks | FWX-SYM-004 |
| Fuzzing (Should) | Protocol names only; seeds, minimization, diagnostic replay, stack dedup absent | Absent | FWX-FUZZ-001–003 |
| Restricted syscall/host surface | Least privilege listed without syscall/host-denial verification | Absent | FWX-SAFE-003 |
| Aggregate concurrency/back-pressure | Absent | Absent | FWX-SAFE-005 |
| Redaction surfaces | No proprietary strings/IP or displayed/logged/telemetry scope | Stored secrets only | FWX-SAFE-006 |
| Authorized audited reveal | Absent | Absent | FWX-SAFE-008 |
| Enforced mentor gate | Human gate named, no approval-record/dispatch check | Not an explicit acceptance condition | FWX-SAFE-009 |
| Immutable audit | Generic audit trail, not append-only or full input/parameter/artifact/finding coverage | Absent | FWX-OBS-001 |
| Telemetry metrics | OpenTelemetry named, metrics/context completeness absent | Tracing only | FWX-OBS-002 |
| Exact API contract | Route concepts, not full /api/v1 signatures or upload/summary responses | “Required functionality” too broad | FWX-API-001–007 |
| Dashboard behavior | View names only; risk sort, per-file hashes, binary/function selection and finding filters absent | “Required views” generic | FWX-UI-001–004 |
| Finding schema | Generic schema, no field/nullability/enums/version coverage | CWE/confidence only explicit | FWX-SCHEMA-001–021 |
| Classification quality | Generic CWE mapping; confidence calibration, heuristic labels and evidence-based dedup absent | Confidence exists, calibration absent | FWX-SCHEMA-022–023, FWX-KPI-004 |
| Delivery details | PR workflow, teardown, real-image versioned schema samples, trade-offs not explicit | Similar omissions | FWX-DELIV-001–003, FWX-DELIV-005, FWX-DELIV-009 |
| Evidence provenance | Real image named at E2E but not all sample provenance/recording form | Generic E2E evidence, no explicit screen recording | FWX-EVID-001–009 |
| Exact KPIs | Performance measurement unspecified; no fixed denominator or representative image | Performance references PRD without <30-minute value; no containment denominator | FWX-KPI-001–005 |
| Ways of working | Daily written stand-up, four increment demos, PR-only landing, extra sensitive review and mentor pairing absent | Absent | FWX-GOV-001–004 |

The safety boundaries in AGENTS.md already reinforce public/licensed inputs, no live targets and nonweaponization. They are now also indexed in the task and acceptance plans. AGENTS.md cleanup, SHA-256 upload identification and final-validation.md remain repository obligations even where not independently specified by the PRD; they are not falsely counted as new PRD requirements.

## Source coverage audit

| PRD part | Disposition |
| --- | --- |
| Document Control, §§1–3 | Scope/safety/vertical slice and architectural goals indexed; business rationale/personas/learning outcomes retained as context, not invented features. |
| §4 | Scope, exclusions, every hard safety boundary indexed. |
| §5 | Components/flow/persistence, audit/telemetry and data fields indexed. |
| §6 | All 16 FR entries retained with original priority: 10 Must, 5 Should (one best-effort), 1 Could. |
| §7 | All 9 SC entries indexed; SC-2.2 also maps to FWX-SYM-004. |
| §8 | Seven exact endpoints and four UI views indexed; representative matrix fields retained. |
| §9 | Required layers and choice guidance indexed; reference tools distinguished from mandatory capabilities. |
| §10 | Every task/deliverable/exit condition mapped to five-day milestones; original sandbox-before-emulation gate preserved. |
| §§11–12 | All deliverables and nine evidence submissions indexed. |
| §13 | Five KPIs and all nine DoD items independently traceable. |
| §14 | Fallback, budgets/merging/incomplete results, containment, extensibility, reveal controls, confidence/dedup retained. |
| §15 | Daily cadence, demo/review, mentor gate, PR review and pairing retained. |
| Appendix A | All 20 leaf fields, enums, nullability and timestamp constraints indexed, plus uniform/versioned schema contract. |
| Appendix B | Mapping reference retained without inventing detector obligations. |
| Appendices C–D | Glossary and recommended references reviewed; no additional normative requirements. |

## Unresolved specifications, not dropped requirements

The standard image set, representative image, exact quotas and mentor identity are unspecified. Propose and freeze these before execution, record provenance and avoid denominator changes after results. The PRD requires real-image sample findings; synthetic fixture results do not fulfill that evidence obligation. If no permitted image yields the required sample, report the unmet evidence gate.

Unredacted artifact access must be gated/audited if exposed; do not add plaintext secret persistence to implement “reveal.” Use restricted original artifacts under explicit authorization. Keep all ordinary outputs fingerprint-only.

No PRD requirement authorizes testing live devices or bypassing containment. Five-day feasibility is a risk, not permission to lower acceptance.
