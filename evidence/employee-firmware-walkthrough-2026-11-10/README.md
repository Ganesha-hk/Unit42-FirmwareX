# FirmwareX employee-to-report walkthrough

Duration: 6 minutes 1 second; 1440 × 1000, 25 fps. Silent automated browser recording with paced typing, pointer movement and pauses. This is not a human-recorded video.

The folder view is an actual local directory served temporarily on loopback; the native OS picker is not captured. The unchanged public OpenWrt image SHA-256 was verified before upload and against the resulting report. Secrets stay masked. No results or file paths were fabricated. Unknown extracted names remain pseudonymized by the application.

## Chapters

- 00:00 — Employee login page
- 00:09 — Register with employee ID, personal password and company code
- 00:29 — Registration fields filled; all secrets masked
- 00:36 — Account created
- 00:48 — Logged in to the workspace
- 00:55 — Browse the actual local OpenWrt firmware folder
- 01:07 — Real downloaded OpenWrt file; .bin is the local upload suffix
- 01:22 — Select the same checksum-verified image for upload
- 01:31 — Public firmware source and license declaration
- 01:42 — Real analysis running; no simulated results
- 01:52 — Analysis overview and inventory counts
- 02:04 — Selected program checks and their completion evidence
- 02:13 — Selected program checks and their completion evidence
- 02:24 — Extracted filesystem explorer; unknown names remain pseudonymized
- 02:32 — Expand a filesystem directory
- 02:38 — Filesystem metadata and hashes
- 02:49 — Binary hardening matrix
- 03:01 — Sort the hardening results
- 03:10 — Twenty review candidates, not twenty confirmed vulnerabilities
- 03:20 — Filter findings by confidence
- 03:29 — Read the redacted evidence behind a candidate
- 03:44 — Control-flow graph from the selected symbolic analysis
- 03:56 — Inspect graph at a closer scale
- 04:06 — Actual job stage timings
- 04:17 — Resource and sandbox metrics
- 04:28 — Export the assessment as JSON
- 04:36 — Security report executive summary
- 04:49 — Report scope and coverage limits
- 05:01 — Detailed findings and recommended review steps
- 05:13 — Finding classification, evidence and next steps
- 05:25 — Image checksum and assessment identity
- 05:35 — Completed report, with bounded selected-check coverage
- 05:45 — HTML report saved for submission
- 05:55 — Logged out; walkthrough complete

## Scope

Shows the available dashboard features on this real assessment. The CFG screen is shown as returned by the app; this recording does not claim every image produces a populated graph. No real-image crash finding is claimed. The original data remains intact; the recording creates one employee account and one new real-image assessment. The employee is logged out and its randomly generated password was not retained.

Files: FirmwareX-employee-to-report.webm, assessment.html, report.json (exact server response), dashboard-export.json (browser JSON export), recording.json, report-preview.png.
