# Unit42-FirmwareX — Agent Instructions

## Authority

PRD.docx is the authoritative specification for this project.

Before implementing anything:
1. Read PRD.docx completely.
2. Read REQUIREMENTS.md.
3. Read ACCEPTANCE.md.
4. Read TASKS.md.
5. Read docs/requirements-traceability.md.

Never silently remove, weaken, reinterpret, or mark a PRD requirement complete
without implementation, verification, and evidence.

If this file conflicts with PRD.docx, PRD.docx wins.

## Project Goal

Build the complete Unit42-FirmwareX firmware-analysis platform described in the
PRD:

firmware upload
→ extraction/rootfs reconstruction
→ filesystem inventory
→ ELF discovery
→ architecture/endianness/bitness detection
→ hardening audit
→ sandboxed cross-architecture QEMU emulation
→ bounded symbolic execution
→ taint analysis
→ secret/crypto scanning
→ normalized CWE findings
→ persistence
→ API
→ dashboard/report
→ observability/evidence.

## Engineering Rules

Build production-quality modular code rather than a mock demonstration.

Do not fake:
- analysis results
- extraction success
- emulation success
- vulnerabilities
- test results
- coverage
- performance numbers
- containment evidence

Mocks may be used only in appropriate unit tests.

Prefer deterministic fixtures and real integration tests.

After meaningful changes:
1. run relevant tests;
2. fix failures;
3. rerun them;
4. record results in docs/progress.md;
5. save required evidence under evidence/.

Do not claim a milestone is complete until its acceptance criteria pass.

## Environment

The project runs inside an Ubuntu x86_64 VirtualBox VM.

Docker Engine and Docker Compose are available.

Do not modify Ubuntu's system Python unnecessarily.
Use isolated Python environments and/or containers.
Pin project dependencies.

Inspect compatibility before selecting Python versions because the host system
Python may be newer than some binary-analysis libraries support.

## Architecture

Use a modular architecture consistent with the PRD.

Expected major components include:

- FastAPI control plane
- PostgreSQL
- Redis
- Celery or RQ worker system
- firmware storage
- Binwalk/extraction layer
- ELF/static-hardening analysis
- QEMU emulation
- symbolic execution/taint analysis
- secret/crypto scanner
- finding normalization/CWE mapping
- reporting
- dashboard
- OpenTelemetry
- sandbox/containment controls

Reference technologies from the PRD include Binwalk, Ghidra headless, angr,
QEMU, Unicorn, checksec and related open-source tooling.

Do not add unnecessary infrastructure merely for complexity.

## Safety Boundary

Analyse only public/open-source firmware that is licensed for analysis or
controlled deterministic test fixtures.

Never target live devices or third-party networks.

All execution/emulation of firmware binaries must occur inside the defined
sandbox.

Sandbox requirements include:
- denied external network egress;
- least privilege;
- restricted filesystem/environment;
- CPU limits;
- memory limits;
- wall-clock timeout;
- cleanup after jobs;
- auditable execution.

Do not emulate arbitrary untrusted firmware until the PRD-required human
containment/sign-off gate has been satisfied.

Controlled test fixtures may be used to develop and verify the harness before
that gate.

## Non-Weaponization

FirmwareX is an analysis system, not an exploitation framework.

Do not generate:
- weaponized exploits;
- functional exploit PoCs;
- shellcode;
- persistence mechanisms;
- destructive payloads.

Crash information must remain diagnostic.

## Symbolic Analysis

Symbolic execution must be bounded.

Implement:
- time budgets;
- state/path budgets;
- memory budgets;
- pruning;
- graceful timeout;
- partial/incomplete-result reporting.

Do not promise exhaustive symbolic execution.

## Secrets

Raw discovered secrets must not persist in normal stored results.

Use redaction and salted fingerprinting as required by the PRD.

Tests must prove plaintext secrets are absent from persisted output.

Never place real credentials in test fixtures.

## Traceability

Maintain:

docs/requirements-traceability.md

Every requirement must eventually map to:

PRD requirement
→ implementation
→ test
→ evidence
→ PASS/FAIL.

Never delete an unmet requirement to make the project appear complete.

## Progress Tracking

Maintain docs/progress.md.

For each milestone record:
- work completed;
- files/modules changed;
- commands used;
- tests executed;
- actual results;
- evidence generated;
- requirements satisfied;
- remaining work;
- blockers/limitations.

## Git

Make coherent commits at meaningful milestones.

Do not commit:
- secrets;
- huge extracted firmware trees;
- database volumes;
- build caches;
- virtual environments;
- temporary analysis output.

Maintain an appropriate .gitignore.

## Definition of Complete

"Complete" means the PRD Definition of Done has been tested against actual
implementation and evidence.

Before final completion create:

docs/final-validation.md

with:

Requirement | Implementation | Test | Evidence | Result

Result must be PASS or FAIL.

Never convert FAIL to PASS without real verification.

## Token / Context Efficiency

Use the available context and tokens aggressively but efficiently.

The goal is maximum useful engineering work per token, not maximum verbosity.

Rules:

1. Do not repeatedly reread unchanged files.
   - Read PRD.docx thoroughly during requirements extraction.
   - Store extracted requirements in REQUIREMENTS.md.
   - Afterward use REQUIREMENTS.md and requirements-traceability.md as the
     working specification, returning to PRD.docx only when clarification or
     verification is necessary.

2. Do not repeatedly explain already-established facts.
   Prefer:
   inspect → implement → test → fix → record result.

3. Keep routine progress messages concise.
   Spend context on:
   - implementation
   - debugging
   - tests
   - requirement verification
   - architecture decisions
   - evidence

   Do not spend large amounts of context narrating obvious actions.

4. Batch related work.
   Examples:
   - inspect related configuration files together;
   - implement closely related modules together;
   - run related tests together;
   - fix related failures in one pass.

5. Search before reading large files.
   Locate relevant symbols/files/sections first, then inspect only the required
   portions.

6. Do not dump large logs into conversation.
   Save full logs under evidence/ or appropriate build/test artifacts and
   summarize:
   - command
   - result
   - important error
   - evidence path

7. Do not paste entire source files after modifying them.
   Summarize changed files and important changes unless full content is
   specifically needed.

8. Avoid unnecessary rewrites.
   Modify existing working code incrementally instead of regenerating modules
   without reason.

9. Avoid speculative implementation.
   Verify existing code, dependencies and interfaces before creating
   replacements.

10. Use automation efficiently.
    Run formatters, linters, tests and validation commands in logical batches
    when doing so does not hide failures.

11. Debug from evidence.
    When something fails:
    - inspect the actual error;
    - identify root cause;
    - make the smallest correct fix;
    - rerun the relevant test.
    Do not repeatedly try random fixes.

12. Keep documentation useful but concise.
    Do not duplicate the same information across many documents. Link/reference
    the canonical document where appropriate.

13. Preserve context across milestones using repository files:
    - REQUIREMENTS.md = canonical extracted requirements
    - TASKS.md = execution checklist
    - docs/requirements-traceability.md = compliance state
    - docs/progress.md = completed work and verification
    - docs/decisions.md = important architecture decisions
    - docs/known-limitations.md = genuine limitations

14. Before beginning a task, inspect the existing progress/traceability state so
    completed work is not unnecessarily repeated.

15. Do not sacrifice correctness to save tokens.
    Token efficiency must NEVER mean:
    - skipping PRD requirements;
    - skipping tests;
    - fabricating results;
    - assuming commands succeeded;
    - omitting security controls;
    - weakening acceptance criteria;
    - replacing real implementation with mocks;
    - marking unverified requirements PASS.

16. Prefer working autonomously through ordinary engineering decisions.
    Ask the user only when blocked by:
    - required human safety/sign-off;
    - credentials/authorization;
    - irreversible external action;
    - genuine material ambiguity in the PRD;
    - a decision that substantially changes project scope.

17. At milestone completion, report only:
    - what was implemented;
    - tests and actual results;
    - requirement IDs satisfied;
    - evidence paths;
    - unresolved failures/blockers;
    - next milestone.

Do not provide lengthy narration unless requested.

Use saved repository state as durable project memory so future tasks can resume
without reconstructing the entire project from conversation history.
