# FirmwareX final validation write-up

Latest cross-architecture follow-up: [controlled E2E validation](cross-architecture-e2e.md) now verifies the full production pipeline and actual dashboard reports on x86_64, ARM32, ARM64, MIPS and MIPSEL. Earlier component-only exports are historical. Full PRD acceptance remains 78 PASS / 34 FAIL; real/vendor execution remains PENDING HUMAN REVIEW.

Current follow-up (2026-10-20): see [completion report](completion-report.md). Lifecycle/output-boundary gaps are addressed within the tested scope; current ledger is 78 PASS / 34 FAIL. Real firmware execution remains **PENDING HUMAN REVIEW**. Review must cover the new telemetry, redaction and privileged historical-maintenance changes. Earlier measurements below are historical.

Current outcome: a working controlled-image analysis platform, with public-image extraction/static/scanner reports and a readable assessment UI. The release is **not accepted** against the full PRD. See task6-review.md for the current evidence and final-validation.md for the complete PASS/FAIL ledger.

## Delivered behavior

Authenticated upload creates a durable job, then a trusted dispatcher runs one isolated offline pipeline: filesystem reconstruction and entropy, ELF hardening and static candidates, gated QEMU service checks and bounded angr/taint, secret/crypto candidates, normalized persistence and reports. The dashboard offers readable names, file metadata, risk sorting, finding filters, interactive CFG and telemetry. JSON remains machine-readable; HTML and print/PDF provide an assessment with severity, confidence, evidence, guidance and explicit limits.

## Engineering decisions and trade-offs

Python 3.12 containers and hash locks avoid breaking system Python or assuming analysis support for Python 3.14. Native tools use a pinned Debian package snapshot. QEMU software emulation is the baseline because KVM is unavailable. A single heavy worker controls aggregate load on the small VM.

Raw reconstruction stays within one sandbox to avoid exporting rootfs contents between tools. Network-none plus same-namespace loopback permits service probing without a routed network. The dispatcher has host Docker authority and is explicitly trusted. /guest is a tightly bounded executable staging area needed by QEMU, while extraction scratch remains noexec. This is subject to mentor and sensitive-code review, not an absolute escape-proof claim.

Angr uses bounded source/sink models rather than exhaustive execution. Unknown object bounds, stripped symbols, architecture ambiguities and extraction limits remain visible. Static imported-function leads are heuristic, not proof of unsafe invocation. Secret/entropy candidates may be false positives; real-image finding counts must not be presented as confirmed vulnerabilities. Unknown firmware-derived names are pseudonymized, trading recognition for confidentiality; user labels provide a separate human-readable identity.

Local OpenTelemetry exports avoid opening worker egress. Current spans do not yet cover every control-plane/failure stage. Buildless UI assets reduce frontend dependency complexity; browser validation tooling still needs portability work for independent reproduction.

## Verification and failures

The final authorized test pass found a decompression-limit integration defect that the small fixture missed. It was corrected and all six frozen public images were rerun successfully. The persistence failure path was made transactional and explicitly audited. Evidence includes unit coverage, controlled cross-architecture runs, guards, quotas, scanner persistence, actual corpus output and a controlled demo recording. Exact counts and limits are in task6-review.md; no static timing is misrepresented as a real-image symbolic benchmark.

## Work required for acceptance

Complete the outstanding engineering requirements and obtain the required mentor/reviewer evidence. Untrusted execution must remain blocked until approval; public-image hashes must never be disguised as controlled fixtures. Run the real-image dynamic benchmark and evidence capture only after that review and a reviewed target-selection implementation. Preserve failures in the final ledger. No compressed schedule changes a PRD Must into an optional item.
