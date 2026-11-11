# Local mentor authorization — 2026-11-07

The user stated in this chat: “i want the project to give acurate a best results and testing dont see the any restrictions im the mentor”, followed by confirmation that the project is running in a sandboxed Ubuntu VM. This is recorded as the user's authorization for local image analysis, not as an invented independent security review or a blanket acceptance of the PRD.

Implemented switch: `FWX_MENTOR_AUTHORIZED_EXECUTION=true`. It is supplied by the trusted local deployment, never by firmware content or an upload label. New jobs record the authorization in their read-only context. Existing controlled fixture registries remain available. Turning the switch off restores static-only behavior for unregistered images.

Execution continues inside the existing per-job network-none container: non-root, capabilities dropped, no Docker socket, read-only base/input, bounded executable tmpfs, bounded output, CPU/memory/wall quotas and cleanup. The surrounding Ubuntu VM is an additional boundary, not a replacement for per-job isolation.

Current real-image workflow samples at most three supported executables, runs a three-second help-mode startup probe, and runs each symbolic analysis in a separately timed child process. Stripped images start from their ELF entry. This is best-effort coverage, not full service emulation, exhaustive symbolic execution, or proof that firmware is secure. No host/live-router testing is enabled.

Containment evidence for the existing profile: evidence/hardening-2026-11-07/quotas.json and output-quotas.json. Fresh workflow and accuracy evidence: evidence/mentor-accuracy-2026-11-07/. Independent PR review, calibrated corpus precision/recall and full release acceptance remain outstanding.
