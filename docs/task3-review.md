# Task 3 — containment and QEMU review

Scope: Day 2 of the five-day plan. Controlled fixture engineering only; human containment approval is outstanding. This is not final product acceptance.

## Delivered design

The trusted Python 3.12 controller validates a separately managed SHA-256 fixture registry before launch. Architecture, arguments, rootfs contents and optional kernel must be allowlisted. Extra files, symlinks, unknown request fields and unregistered inputs fail closed. There is no caller-provided approval flag. The registry is an operator trust boundary and must never be populated from an upload. The current interface deliberately cannot run arbitrary firmware, even if its upload provenance says “controlled.”

QEMU user-mode adapters cover MIPS big endian, MIPSEL, ARM32, ARM64 and x86_64. The production sandbox launcher supplies a read-only container, non-root UID, no capabilities, Docker's default seccomp/AppArmor policy, no-new-privileges, bounded scratch/tmp, PID/CPU/memory/wall limits and forced removal. Actual container configuration and image identity are recorded with each result. The Docker socket is confined to the trusted launcher. QEMU workers receive no socket, host devices or KVM. Software translation is the supported path on this VM.

HTTP, SSDP/UPnP and MQTT clients run alongside the emulated service in the same per-job network namespace. The only interface is loopback: no veth, route, bridge or published port. This provides service reachability without exposing a service to the host. These are protocol reachability probes, not fuzzers; fuzzing remains Day 4 work.

Each allowed attempt appends start/finish events to the existing immutable PostgreSQL audit table, including input hashes, parameters, image and quotas. Gate denials append a payload-free refusal. Normal output contains status, sizes, hashes and bounded telemetry, not guest stdout/stderr. Full pipeline dispatch/recovery and OpenTelemetry integration remain Day 4 obligations.

## Best-effort full-system behavior

Named QEMU machine profiles use TCG and no NIC. A controlled ARM bare-metal fixture exercises the virtual PL011 UART and timeout/fallback path. Its boot marker is checked by hash; it is not a Linux or vendor firmware boot. Missing kernels and bounded boot timeouts return explicit incomplete status and a user-mode fallback recommendation. No automatic retry runs an unapproved input.

A minimal read-only `nvram_get`/`nvram_set` shim provides synthetic loopback defaults, returns null for unknown keys and refuses writes. Its ABI is verified using a controlled ARM program. It is a linking aid for compatible controlled targets, not a universal drop-in vendor NVRAM replacement. Board-specific peripheral models and proprietary NVRAM ABIs remain unsupported; QEMU's generic virtual board peripherals are the current supported models. FR-2.2 remains best-effort, with real vendor userland/service boot unverified.

## Reproduction

Prerequisites: Task 2 native/control/fixture images and local Compose configuration; do not replace system Python.

1. Build `infra/images/qemu/fixtures.Dockerfile` as `firmwarex-emulation-fixtures:task3` and `infra/images/qemu/Dockerfile` as `firmwarex-qemu:task3`.
2. Run `scripts/build-emulation-fixtures.sh` in the fixture builder, with sources mounted at `/sources` and `work/fixtures` at `/fixtures`. This compiles; it does not execute targets.
3. Compare generated hashes with `fixtures/manifests/emulation-controlled.json`. A mismatch requires source/build review, not automatic registration of an arbitrary binary.
4. Start Compose PostgreSQL and Redis. Run `scripts/verify-emulation.py` in a trusted dispatcher container, mounting current `src` at `/app/src`, scripts at `/scripts`, `work/fixtures/emulation` at `/fixtures`, manifests at `/registry`, and evidence/task3 at `/evidence`.
5. Run `tests/unit/test_emulation.py` and the existing static regression tests in the control image with fixture mounts. Save JUnit output.

See `evidence/task3/` for execution records, actual image IDs, package versions, JUnit results and packet capture. Native packages resolve against the inherited fixed Debian snapshot; application Python remains the pinned isolated 3.12 runtime. QEMU packages retain Debian license metadata in the image.

## Review gate

Mentor must review the exact code/image revision, container profile, quota results, packet evidence, registry trust boundary and failure cleanup before untrusted emulation can be enabled. Record reviewer, date, reviewed commit/image IDs and decision. No approval has been granted or inferred. Sensitive sandbox code also needs PR review. GitHub publication remains subject to the user's separate approval.

Remaining product work: symbolic/taint analysis, secrets/redaction, normalized findings, full pipeline integration, reports/dashboard, tracing, final performance/coverage and real-image end-to-end acceptance.

## Verified results

- 29 unit/regression tests passed, with no test errors or warnings in the final run.
- 36 QEMU integration cases passed: ten repeat user-mode runs, fifteen service probes, five guest containment checks, three quota terminations, missing-kernel fallback, controlled ARM boot/timeout, and NVRAM stub contract.
- Twenty service/guest-containment repeats passed during host packet observation. Exactly one observer positive-control packet was captured on host loopback; no tested guest traffic was observed. Capture reported zero kernel drops. Filter: ports 18080 and 45678. `egress.pcap` intentionally contains that positive-control packet, not an escaped guest packet.
- Unregistered input was denied before container launch and recorded in PostgreSQL. Static launcher quota/network regression also passed after shared launcher changes.
- All integration cases verified container cleanup and start/finish audit records. Binary registry hashes match the compiled controlled artifacts.

Retained failure logs document stopped database dependencies, unordered audit-test reads, the boot fixture's CPU/linker setup corrections, an observer privilege/buffering setup issue and a Docker-client test API misuse. Final reruns above passed. These earlier failures are not omitted from the evidence archive.

Scoped requirement coverage: FWX-EMU-001, FWX-EMU-002, FWX-EMU-004, FWX-SAFE-002/003/004 and FWX-DELIV-008. FWX-EMU-003 is partial/best-effort; FWX-ARCH-004 and FWX-SAFE-001 remain in progress across later stages. FWX-SAFE-009 remains blocked on actual mentor sign-off. See requirements traceability for precise status.
