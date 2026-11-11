# Task 4 — bounded symbolic analysis and secret/crypto findings

Scope: Day 3 of the saved execution plan. This milestone is a controlled analysis component and persistence implementation, not the integrated application or final PRD acceptance. The upload API remains static-only until the next milestone.

## Implementation

The analysis image extends the hash-locked Python 3.12/angr runtime. angr 10 exposes its symbolic-expression engine as `angr.claripy`; the implementation uses the installed API. No change to system Python or dependency version was needed. Sources model CGI stdin (`read`), network buffers (`recv`), CGI `QUERY_STRING`, and other environment input (`getenv`). These models use bounded printable symbolic bytes and do not open real network connections.

Taint follows symbolic AST dependencies through VEX-executed target instructions and memory. Hooks inspect strcpy, memcpy, sprintf, system and popen. Commands are never invoked. The supported sprintf `%s` case checks destination bounds; symbolic format strings produce a separate CWE-134 candidate. Other formats return incomplete analysis. Safe bounded copies preserve symbolic memory; paths terminate at candidate violations rather than performing damaging copies. Findings are probable/heuristic, not claims of confirmed exploitable vulnerabilities.

ELF object symbols supply global bounds; modeled malloc supplies heap bounds. DWARF array/object size and frame offsets support the tested x86_64 frame-pointer stack ABI. Unknown bounds are explicitly heuristic CWE-120 leads, not invented overflow offsets. A candidate out-of-bounds write includes the first modeled invalid address and object-relative offset. An actual symbolic invalid-memory-access fixture exercises the engine fault diagnostic. No concrete exploit input, shellcode or command is emitted.

Evidence contains symbolic reaching constraints, source identifiers, address paths, call path, diagnostic registers and stack hash. Data registers are fingerprinted; address registers remain numeric for diagnostics. The normalized finding has exactly the PRD Appendix A fields. Referenced evidence carries condition/model information rather than adding non-PRD top-level fields. UUID5 identifiers and firmware-private salted evidence identifiers support repeated-run deduplication.

Exploration has time, memory, path, state, depth, step and source-size budgets. Unsatisfiable states are pruned. Compatible states merge while preserving alternative path addresses. Exceeding a budget yields incomplete status with a reason; the outer container watchdog independently enforces hard CPU/memory/wall limits and cleanup. The controller rejects unknown request/budget fields and invalid types before launch. Arbitrary binaries remain blocked by a separately reviewed controlled-fixture hash registry.

The scanner detects credential assignments, private-key/certificate blocks, high-entropy strings and weak crypto in security-related lines. It emits only rule, offset, length and HMAC-SHA256 fingerprint. Certificate/entropy/crypto-context detections remain heuristic review leads. Non-security MD5 checksum text is a negative case. This is not a claim that every high-entropy token is a credential or every certificate is secret.

Private per-firmware random salts reside under restricted storage; they never enter result/audit records. A strict persistence boundary validates the Appendix A schema and rejects free-text diagnostic fields. The database stores deduplicated findings and redacted evidence, with append-only audit events. A separate fail-closed redaction utility fingerprints arbitrary firmware strings and dictionary keys for later display/export integration. Raw reveal is disabled and attempts through its interface are denied and audited; there is no approved reveal path yet.

## Limits and review gates

- Source models are bounded, not exhaustive. Unknown imports, device semantics, missing symbols and unsupported format/ABI behavior require additional models and may produce incomplete results.
- Supported stack-bound inference is narrow; stripped binaries do not gain invented debug information. A probable tainted sink is not a concrete exploit proof.
- Arbitrary vendor firmware has not been symbolically executed. Mentor containment sign-off remains required before enabling it.
- Scanner coverage is heuristic and bounded to 16 MiB per file. Binary DER key/certificate parsing, encodings and domain-specific crypto semantics need future extension; PEM headers and text/config contexts are the tested scope.
- The redaction utility and finding boundary do not retroactively sanitize all existing static inventory/API fields. Universal endpoint/log/trace/export redaction and full pipeline integration remain open PRD obligations.
- No dashboard/report endpoint, OpenTelemetry, representative-image symbolic KPI, or final product acceptance is claimed here.
- Sensitive analysis/redaction/sandbox code needs human PR review. No GitHub publication is authorized automatically.

## Reproduction

1. Build controlled fixtures with `scripts/build-analysis-fixtures.sh` inside `firmwarex-emulation-fixtures:task3`, mounting sources at `/sources` and work/fixtures at `/fixtures`. Targets are compiled, never executed on the host.
2. Compare hashes with `fixtures/manifests/analysis-controlled.json`; review any changes before updating the trusted registry.
3. Build `infra/images/analysis/runner.Dockerfile` as `firmwarex-analysis:task4`.
4. Start local PostgreSQL/Redis, and run migration 0002 with current migrations mounted into the migrate service.
5. Run scripts/verify-analysis.py, verify-redaction.py and verify-analysis-guards.py in the trusted dispatcher with current source, scripts, fixture, registry and evidence mounts. The source-to-sink runner launches every target inside the production no-network sandbox.
6. Run the unit suite in the control container with fixture mounts; save JUnit and the scoped scanner/schema coverage report.

Evidence is under `evidence/task4/`. Failed development attempts are retained beside final reruns. Coverage percentages apply only to the named unit-tested modules, not the whole product or symbolic engine.

Implementation references checked against official angr documentation: [simulation-manager merging](https://docs.angr.io/en/v10.0.2/api/angr.sim_manager.html), [exploration techniques](https://docs.angr.io/en/latest/api/angr.exploration_techniques.html). The tested installed runtime and real fixtures are the compatibility authority for this milestone.

## Verified results

- 73 unit/regression tests passed, including schema rejection, scanner positives/negatives, arbitrary-content redaction and existing static/emulation checks.
- 42 symbolic integration cases passed. The matrix covers 24 combinations of four source models and six sink behaviors; intermediate-copy taint propagation; three negative/safe cases; stack/heap/fault diagnostics; six budget stops; merging; and four additional architecture runs.
- Two scanner runs stored eight unique findings with stable identifiers. Synthetic plaintext was absent from result files, persisted findings, evidence and audit rows; stored fingerprints matched the protected salt.
- Eight malformed/unregistered requests were refused before launch; raw reveal was denied and audited. The outer watchdog terminated a real analysis container and returned incomplete status with verified cleanup.
- A clean disposable database passed upgrade, downgrade to 0001 and re-upgrade to 0002. Three existing HTTP/upload/queue/static-sandbox scenarios passed after the control image rebuild.
- Unit coverage of findings/scanners/redaction modules is 92% (79/86 statements). The denied-reveal branch is covered by the separate real database test; this number is not product-wide coverage.

Development failures retained in evidence include the angr import compatibility fix, stopped local services, controlled-fixture file ownership/registry sequencing, an API request racing service startup, and recovery of the actual fault-time state from angr error tracebacks. Final successful logs and summary are the acceptance evidence, not those failed attempts.
