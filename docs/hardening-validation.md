# Hardening validation — 2026-11-07

This is a scoped engineering evidence record, not a declaration of universal safety or final PRD acceptance.

| Change | Verification | Evidence |
| --- | --- | --- |
| Upload handler runs blocking database/file operations in the thread pool | Four concurrent 4 MiB uploads; 93 health probes; maximum observed health latency 0.234 seconds | `../evidence/hardening-2026-11-07/concurrent-uploads.json` |
| Output storage bounded to 40 MiB and 1,024 inodes; only a bounded regular JSON file copied to host | Byte, inode, oversized artifact, symlink and malformed JSON probes | `../evidence/hardening-2026-11-07/output-quotas.json` |
| CPU, memory, time and network isolation | Four production sandbox workload tests | `../evidence/hardening-2026-11-07/quotas.json` |
| read/recv source models preserve adjacent bytes; getenv has bounded termination | 13 real angr state cases | `../evidence/hardening-2026-11-07/source-models.json` |
| Failed dynamic stages preserve static/scanner results; enum values survive sanitization | Regression unit suite | `../evidence/mentor-accuracy-2026-11-07/unit-tests.xml` |
| Core controlled pipeline | Full upload-to-persistence and API verification | `../evidence/mentor-accuracy-2026-11-07/regression/pipeline-results.json` |
| Dashboard interactions, export, mobile layout | Ten interaction groups, no browser errors | `../evidence/mentor-accuracy-2026-11-07/regression/browser-results.json` |

The latest recorded unit run has 128 tests, zero failures and zero errors (9.49 seconds), including the final optional-stage additions. Whole-package unit coverage is 35.94% (716/1,992 lines); separately executed integration workloads are excluded. Dedicated optional-stage evidence is recorded in release-readiness.md.

## Finding accuracy changes

Scanner records now stop at NUL/newline boundaries and bound nearby security context. A public certificate is an observation, not a private-key vulnerability. Entropy alone is counted as an observation and does not establish a credential. Common code placeholders are excluded. Private-key markers remain heuristic pending structural/usage validation. Static function symbols remain heuristic leads with invocation/overflow explicitly unproven.

The same uploaded `demo` SHA-256 produced 474 candidates before these fixes and 53 afterward, with 610 filesystem entries and 156 audited binaries unchanged. This is a change in alert volume, **not a precision or recall measurement**. Manufacturer/model attribution of this upload has not been verified. Evidence: `../evidence/mentor-accuracy-2026-11-07/comparison.json`.

## Real-image execution scope

User mentor authorization is recorded in mentor-authorization.md. The local deployment enables `FWX_MENTOR_AUTHORIZED_EXECUTION`; new jobs receive the authorization through trusted context. At most three supported application executables receive help-mode probes and separate bounded symbolic analysis. Libraries are excluded from startup selection. The child environment includes a fixed non-root username needed by pyvex. Program-entry analysis explicitly records limited startup models.

Help-mode exit success does not prove service boot, exploitability, or exhaustive coverage. Partial states are retained. Per-job isolation and quotas remain enforced within the Ubuntu VM.

## OpenWrt service verification — 2026-11-08

The frozen OpenWrt registry selects a BusyBox true-applet check and an isolated uhttpd HTTP harness. uhttpd initially returned HTTP 403 because its content permission check rejected the synthetic page under umask 077. Only that synthetic directory/page now receive modes 0755/0644; firmware files and sandbox settings are unchanged. The real service now returns HTTP 200 with the exact synthetic marker, in both an isolated diagnostic and the full queued pipeline. Responses are fingerprinted, not stored as raw firmware content.

`service-verified/comparison.json` records the repaired reanalysis; `openwrt-demo/report.json`, `demo.json`, `demo-report.png` and the referenced WebM record a fresh UI upload-to-report run. The recording's last frame was decoded and visually checked. Dashboard regression passes all ten interaction groups, including export and mobile layout. All 128 unit tests pass. The service result does not establish full board boot, original vendor application behavior, or completed symbolic analysis.
