# Unit42 FirmwareX

FirmwareX analyzes public firmware images in an isolated local environment. It extracts files, inspects binary protections, runs selected emulation and bounded symbolic checks, and saves findings with evidence in an authenticated dashboard.

## Project report

[Read the project report (PDF)](docs/submission/FirmwareX_Project_Report_Ganesha_hk.pdf)

The report follows the internship assessment structure, with real application screenshots, measured results, local setup instructions and a reflection. It documents the remaining limitations alongside the working features.

## Verified results

- Real image: OpenWrt 24.10.4 x86/64 SquashFS root filesystem.
- 1,571 filesystem entries and 171 ELF binaries inventoried.
- BusyBox utility check, uhttpd HTTP-response check and one bounded cgi-io header/empty-body symbolic path completed.
- 20 static/scanner candidates; these are **not 20 confirmed vulnerabilities**.
- 170 unit tests passed, including 11 employee authentication tests; real browser registration/login/logout checks passed.
- A separate scoped benchmark measured 4.209340868 seconds for static plus selected analysis. This is not a whole-firmware performance guarantee.

**Selected checks complete does not mean entire firmware verified.** The requirement ledger remains 105 PASS / 7 FAIL. Real-image crash validation and independent clean-machine reproduction are still outstanding. See [supported OpenWrt scope](docs/openwrt-supported-profile.md), [employee access](docs/employee-access.md), and [full ledger](docs/final-validation.md).

## Main features

- Employee ID/password login and company-code registration.
- Upload queue, persistent assessments and preserved reanalysis history.
- Filesystem explorer, ELF architecture detection and binary hardening matrix.
- Selected QEMU emulation and bounded angr symbolic analysis.
- Redacted secret/crypto candidates with CWE, confidence and evidence.
- Graph viewer when graph data exists; the recorded OpenWrt report has no populated CFG export.
- Stage timings, sandbox resource metadata, HTML reports and JSON export.

The stack uses FastAPI, PostgreSQL, Redis, Celery, Docker, QEMU and angr. All employee accounts currently share the same workspace. The shared onboarding code is not HR identity verification.

## Local setup

Use an Ubuntu/Linux host with Docker Engine and Compose. Analysis runs in containers; ordinary host Python 3 is used for the configuration helper. Do not install application dependencies into system Python.

```sh
git clone https://github.com/Ganesha-hk/Unit42-FirmwareX.git
cd Unit42-FirmwareX
python3 scripts/bootstrap.py
docker build -f infra/images/extract/Dockerfile -t firmwarex-native:day1 .
docker tag firmwarex-native:day1 firmwarex-static:day1
docker build -f infra/images/qemu/Dockerfile -t firmwarex-qemu:task3 .
docker build -f infra/images/pipeline/Dockerfile -t firmwarex-pipeline:task5 .
docker compose build api
docker compose up -d
```

Bootstrap creates a private `.env` and `.runtime` directory and refuses to overwrite an existing configuration. Wait for `http://127.0.0.1:8000/health`, then open `http://127.0.0.1:8000/`. Register with an employee ID, password and the privately provided `FWX_COMPANY_REGISTRATION_CODE`. Do not commit the generated configuration.

New configurations default to restricted/static behavior for unregistered images. The prepared local OpenWrt demonstration uses the explicit bounded-execution configuration documented in [the supported profile](docs/openwrt-supported-profile.md). Building controlled test fixtures is separate; follow [testing instructions](docs/testing.md). A fresh independent setup has not yet been validated end to end.

For an existing configuration, `python3 scripts/configure-employee-access.py --env-file .env` adds a company code if absent; then recreate the Compose services. The separate evaluation instance described in the report uses `work/submission-instance/.env`, project name `firmwarexsubmission` and port 8001. These private files are not included here.

## Real firmware input

Download the `generic-squashfs-rootfs.img.gz` image from the [official OpenWrt 24.10.4 x86/64 directory](https://downloads.openwrt.org/releases/24.10.4/targets/x86/64/). The expected SHA-256 is:

```text
8c88c338afad0535ab295a62e9555dc91f3bf5c8f4fc3bc67008adb2619f60e6
```

The current uploader accepts `.bin` and `.img`; append `.bin` to the downloaded filename without extracting or changing its bytes. Choose public open-source provenance and provide the official source URL. Firmware binaries are not distributed in this repository.

## Evidence and operation

[evidence/employee-access-2026-11-10](evidence/employee-access-2026-11-10) contains the latest unit test log and browser verification summary. [evidence/employee-firmware-walkthrough-2026-11-10](evidence/employee-firmware-walkthrough-2026-11-10) contains the real assessment and HTML export. [evidence/submission-real-2026-11-10](evidence/submission-real-2026-11-10) contains the separate benchmark and persistence evidence.

Historical evidence directories retain their original dates and counts. Videos and private runtime data remain in the local submission package; they are omitted from this source repository. Recorded manifest files may refer to those separately supplied video files.

The API supports private Bearer-token automation and employee cookie sessions. Browser mutations require matching Origin. Passwords are salted hashes; sessions expire and logout revokes them. The deployment is loopback-only. A future HTTPS deployment must configure secure cookies and trusted proxy handling.

The trusted dispatcher has Docker-daemon access; individual analysis jobs do not. Jobs use network isolation, a read-only container root and resource limits. An ordinary hosted web service is not a substitute for this execution environment.

```sh
docker compose down
```

Stopping without `-v` preserves database volumes and firmware storage. Do not delete volumes or runtime directories unless you intend to remove those records.

## Licence

This repository retains its Apache-2.0 licence. Third-party tools and downloaded firmware have their own licences; the repository licence does not relicense them.
