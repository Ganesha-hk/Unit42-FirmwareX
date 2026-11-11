# FirmwareX — real firmware assessment and submission record

Date: 10 November 2026. This is the current submission summary; older evidence directories record earlier runs.

## Outcome

A fresh local instance with empty PostgreSQL, Redis and input storage processed the real OpenWrt 24.10.4 x86/64 SquashFS root-filesystem image through upload, extraction, static audit, selected emulation, bounded symbolic execution, secret/crypto scanning, persistence and the dashboard. No synthetic firmware image was uploaded to this instance. Controlled fixtures remain in the repository for regression tests and are not represented as vendor evidence.

The assessment contains 1,571 filesystem entries and 171 ELF binaries. The selected runtime checks are BusyBox's `true` applet, a real uhttpd HTTP response serving a synthetic test page inside the isolated job, and a cgi-io symbolic multipart-header/empty-body scenario. The symbolic result records 54 steps, one path, terminal register value 0 and no findings. The dashboard displays **Selected checks complete**. This does not establish complete upload parsing or whole-firmware coverage.

## Image provenance

- Image: `openwrt-24.10.4-x86-64-generic-squashfs-rootfs.img.gz.bin` (the `.bin` suffix is the local upload filename).
- SHA-256: `8c88c338afad0535ab295a62e9555dc91f3bf5c8f4fc3bc67008adb2619f60e6`.
- Frozen provenance: `fixtures/manifests/openwrt-24.10.4.json`, including the official download URL and component-license caveat.
- The local image checksum was recomputed before the new upload. No firmware binary was patched to obtain the result.

## Measured results

| Measurement | Result | Scope |
| --- | --- | --- |
| Static plus selected analysis | 4.209340868 seconds | Interval from static start to vendor-analysis end, including real emulation and selected symbolic work |
| Analysis pipeline | 6.106506714 seconds | Pipeline span; not browser time, queue time or a sum of nested spans |
| Throughput target | PASS for declared profile | Strictly below 1,800 seconds; no general vendor throughput claim |
| Unit tests | 159 passed | Current implementation, isolated container |
| Classification and symbolic regressions | See verification logs | Controlled cases; not independent vendor precision/recall |

The benchmark records CPU model, memory, CPU count, actual sandbox image ID, limits, exact symbolic budgets, coverage, timestamps, and the report checksum. The historical benchmark helper summed overlapping spans; use `scripts/benchmark-real-report.py` instead.

## Findings and accuracy

The real report contains 20 candidates: ten static dangerous-function-symbol leads, four credential patterns, three private-key patterns, and three weak-crypto patterns. These counts are detector outputs, not twenty validated vulnerabilities. Static symbol presence does not prove unsafe execution; textual credential/key patterns require contextual validation. No real-image memory-corruption finding was validated. The zero-finding CGI result does not satisfy the PRD's request for a real taint-to-sink crash finding.

The regression tests distinguish safe copies, undersized allocations, and truncated symbolic allocations. Excluded allocation ranges retain incomplete status. The errno/EOF fixture requires recorded return value zero. These checks improve model correctness but are not a general accuracy percentage.

## Reproduction and evidence

Evidence directory: `evidence/submission-real-2026-11-10/`.

- `server-report.json`: exact server report and authoritative integer timestamps.
- `report.json`: initial browser export rounded large integers; the recording helper now preserves raw JSON for future runs.
- `assessment.html`: downloadable application-rendered report.
- `demo-report.png`, `video/`, `demo.json`: recording and selected run identity.
- `benchmark-exact.json`: authoritative timing/configuration from exact server integers.
- `benchmark.json`: initial browser measurement retained for traceability; sub-microsecond rounding does not change the outcome.
- `filesystem.json`, `mitigation-matrix.json`, `candidate-findings.json`: extracted report sections.
- `reproduction.json`: fresh-state and persisted-report checks after teardown/restart.
- `verification/`: unit and controlled regression logs, cache archive record.

The separate instance uses port 8001 and private `work/submission-instance/.env`. Run the following from the project directory:

```sh
python3 scripts/prepare-submission-instance.py
docker compose --env-file work/submission-instance/.env -p firmwarexsubmission up -d
```

The helper runs once and refuses to overwrite an existing configuration. Open `http://127.0.0.1:8001/`. Read the token privately from that instance's `.env`; do not include it in submission files. For the browser verifier set `FWX_ENV_FILE=work/submission-instance/.env`, `FWX_BASE_URL=http://127.0.0.1:8001`, a new `FWX_EVIDENCE_DIR`, and the installed Playwright module path. `FWX_EXPECT_EMPTY=1` asserts that the first recording starts with no assessments. Omit it for subsequent uploads.

```sh
docker compose --env-file work/submission-instance/.env -p firmwarexsubmission down
docker compose --env-file work/submission-instance/.env -p firmwarexsubmission up -d
```

Teardown retains volumes and reports. This is same-host fresh-state reproduction with existing Docker images, not an independently reproduced clean-machine installation.

## Remaining requirements

The real taint-to-sink/crash evidence requirement remains unmet. Independent fresh-machine reproduction and broader vendor accuracy calibration are unverified. Wider emulation, symbolic body parsing, hardware support, real-service fuzzing and vendor snapshots remain coverage extensions; exhaustive firmware verification is not promised by the PRD. Required review records are separate from technical test results.

For the recording: demonstrate the real image upload, file inventory, hardening table, stage details, candidate findings and downloadable report. Say: “FirmwareX completed the declared checks on this OpenWrt image. The report shows their evidence and coverage limits; candidates require validation.”
