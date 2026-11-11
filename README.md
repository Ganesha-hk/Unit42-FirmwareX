# Unit42 FirmwareX

FirmwareX is a self-hosted workspace for inspecting embedded Linux firmware images. Upload an image, inspect its extracted files and binary protections, run supported checks, and review findings with their evidence.

It analyzes **firmware files**, not live routers or third-party networks. The current deployment is intended for a trusted internal team on a dedicated Linux host. It is not yet a complete multi-tenant production service.

## Authorized testing only

FirmwareX is intended only for educational testing, security research and **authorized firmware analysis**. Use it only with public open-source firmware whose licence permits your intended use, or controlled test fixtures you own or are authorized to analyze. Public availability alone does not grant permission for every use.

Do not use this project to damage devices, modify third-party systems, access networks without permission, or conduct malicious activity. The documented workflow analyzes image files in isolated containers; it does not flash a device or intentionally alter the original source image. This is a design intention, not a guarantee that running the software is risk-free. Keep backups and use an isolated test environment.

The OpenWrt images referenced in this repository are test inputs obtained from their official source. Firmware binaries are not included in the current repository, and their licences and ownership remain with their respective authors. References to OpenWrt do not imply endorsement or affiliation.

Users are responsible for obtaining permission, complying with applicable laws and licences, and the consequences of their use. The project is provided **as is**, without warranties. To the extent permitted by applicable law and the Apache-2.0 licence, the authors and contributors accept no liability for misuse, damage, data loss or other consequences arising from its use. See [LICENSE](LICENSE) for the governing terms.

## What you can use it for

- Review the contents and attack surface of a firmware release before deeper manual analysis.
- Identify binaries missing compiler/linker protections such as NX, PIE, RELRO or stack canaries.
- Investigate credential patterns, weak cryptography and potentially dangerous function usage.
- Run selected service checks and bounded symbolic analysis for supported firmware profiles.
- Keep assessment history and export findings for engineering review.
- Teach or demonstrate firmware-analysis workflows using licensed public images and controlled fixtures.

Findings are candidates for investigation. Missing protections or a matching string do not prove exploitation. A completed selected check does not mean every program in an image has been verified.

For a fresh client machine, follow [Client setup](docs/CLIENT_SETUP.md). It lists what is included, host prerequisites, first login, sample input, tests and updates.

## Quick start

### Requirements

- Linux x86-64 host or Ubuntu VM, with Docker Engine and Docker Compose v2 installed.
- Git and Python 3 on the host; application Python 3.12 is installed inside containers.
- A normal user with permission to use Docker. Do not run the bootstrap as root.
- Internet access for the initial image/dependency builds. Analysis jobs themselves have external network access disabled.
- Enough disk space for Docker images, uploaded firmware, extracted files and the database. For initial evaluation, allow around 20 GB free and 4 GB RAM; these are planning estimates, not a validated minimum.

Install Docker using its [official Ubuntu instructions](https://docs.docker.com/engine/install/ubuntu/) if needed.

```sh
git clone https://github.com/Ganesha-hk/Unit42-FirmwareX.git
cd Unit42-FirmwareX
sh scripts/start.sh
```

The repository is private unless its owner changes visibility; cloning requires access. The first run builds the native, QEMU, pipeline and API images in dependency order. It generates private credentials, starts PostgreSQL and Redis, applies database migrations and waits for the API to respond.

Open **http://127.0.0.1:8000/** on the same machine.

The script preserves an existing `.env`. To start again without rebuilding images:

```sh
sh scripts/start.sh --no-build
```

`/health` confirms HTTP liveness. Check the Compose service status and perform a login/upload smoke test as well; that endpoint does not test every dependency.

### Create an employee account

1. Open the website and choose **Create an account**.
2. Enter an employee ID, a password of 12-128 characters, and the password confirmation.
3. Enter the `FWX_COMPANY_REGISTRATION_CODE` from the private `.env`, supplied by the administrator.
4. Log in with only the employee ID and password.

Employee IDs are case-insensitive. The registration code is a shared onboarding secret, not a one-time invitation or HR identity verification. All employees currently share one workspace. Accounts use hashed passwords and eight-hour sessions; logout revokes the session. Keep `.env`, company codes and passwords out of recordings and Git.

For a configuration created before employee registration was added:

```sh
python3 scripts/configure-employee-access.py --env-file .env
docker compose up -d --force-recreate api
```

## Run your first assessment

1. Obtain an image you are permitted to analyze. Select a `.bin` or `.img` file in the upload form.
2. Give the assessment a recognizable name, such as `OpenWrt 24.10.4 - Router firmware review`.
3. Select public open-source provenance and enter its source URL and license declaration, or use a controlled fixture with its matching declaration.
4. Start analysis and wait for the stage results.
5. Inspect File explorer, Binary hardening, Findings & evidence, and Job telemetry.
6. Open the readable report or export JSON. Use **Run again** for a new assessment while retaining the original.

For the tested real-image profile, use the `generic-squashfs-rootfs.img.gz` download from the [official OpenWrt 24.10.4 x86/64 directory](https://downloads.openwrt.org/releases/24.10.4/targets/x86/64/). Append `.bin` to its name without extracting or modifying it. Expected SHA-256:

```text
8c88c338afad0535ab295a62e9555dc91f3bf5c8f4fc3bc67008adb2619f60e6
```

Alternatively, `python3 scripts/fetch-corpus.py` downloads and verifies the six public images in the versioned manifest into ignored `work/corpus/`. It downloads images only; it does not execute them.

### Enable bounded real-image execution

New configurations leave execution of unregistered images disabled. Static/scanner results remain available, and runtime stages explain that execution is disabled.

For a trusted, isolated analysis host, set this existing compatibility setting in `.env`:

```dotenv
FWX_MENTOR_AUTHORIZED_EXECUTION=true
```

Despite its legacy name, this is the current technical switch for bounded vendor-image execution; it is not an employee role. Recreate services after changing it:

```sh
docker compose up -d --force-recreate api dispatcher scheduler
```

This permits the bounded vendor-analysis route for submitted images, not only OpenWrt. It does not add support for unknown hardware, libraries or services. Unsupported analysis still returns incomplete. Restrict upload access to trusted users and keep analysis containment enabled.

## How it works

```text
Employee login -> image upload -> PostgreSQL job record / Redis queue
  -> Celery dispatcher -> isolated Docker analysis job
  -> extraction and filesystem inventory
  -> ELF architecture and hardening inspection
  -> selected QEMU service checks
  -> bounded symbolic analysis and secret/crypto scanning
  -> normalized findings and redacted evidence
  -> stored assessment -> dashboard / HTML and JSON exports
```

The browser polls the API for progress. PostgreSQL retains jobs, findings, employee accounts and sessions. The dispatcher has Docker-daemon access; the analysis containers do not receive that socket or the application credentials.

Jobs use a read-only container root, a non-root user, dropped Linux capabilities, no privilege escalation, disabled external network, and CPU/memory/process/time limits. A service harness can use isolated loopback inside a job. This is not complete emulation of a physical router.

## Tools used in the backend

| Tool or component | Actual role |
| --- | --- |
| FastAPI + Uvicorn | Authentication, upload API, dashboard and report endpoints |
| PostgreSQL + SQLAlchemy + Alembic | Persistent data, database access and schema migrations |
| Redis + Celery | Work queue, scheduling and authentication attempt limits |
| Docker Engine / Compose | Control services and restricted analysis containers |
| Binwalk | Firmware signature inspection |
| SquashFS tools, libarchive, e2fsprogs, mtd-utils, cpio | Supported filesystem/archive extraction and inspection |
| pyelftools and project static-analysis code | ELF metadata and protection checks |
| QEMU user/system emulators | Selected program/service execution and controlled system-emulation fixtures |
| angr + Claripy/Z3 | Bounded symbolic execution, input models and constraint solving |
| Unicorn | Supporting emulation dependency and controlled runtime smoke checks; not a universal firmware emulator |
| GDB multiarch | Diagnostic/debugging tooling for supported analysis workflows; not run for every binary |
| checksec | Installed in the fixture compiler image for manual/reference checks; dashboard hardening uses project ELF analysis |
| OpenTelemetry | Recorded stage timings and metrics |
| pytest | Unit regression tests |

Ghidra is not integrated into the current automated pipeline. The project does not perform an automatic CVE-database lookup, assign CVSS scores, or prove that every scanner candidate is exploitable.

## Supported scope and current limits

The selected OpenWrt profile checks the BusyBox `true` applet, a uhttpd HTTP response and one cgi-io multipart-header/empty-body symbolic path. The recorded real image contained 1,571 filesystem entries and 171 ELF binaries. Three programs were selected; only one had a symbolic profile. Its completed analysis does not cover complete request bodies or every binary.

- Other firmware may lack the required libraries, startup model or service harness and return partial/incomplete results.
- Static function names and credential/crypto patterns are candidates, not confirmed vulnerabilities.
- Unknown extracted names can be pseudonymized; raw secret reveal is disabled.
- The graph viewer requires exported graph data. The tested OpenWrt assessment does not contain a populated CFG export.
- Controlled fuzzing/replay and snapshot functionality do not establish arbitrary vendor fuzzing or hardware support.
- There is no independently validated real-image crash example or broad vendor precision/recall measurement.
- Account recovery, employee administration, roles, workspace separation, high availability and multi-node dispatch are not implemented.

## Tests

After building the application images:

```sh
sh scripts/test.sh
```

This builds controlled fixtures inside a compiler container and runs the unit suite offline. No host compiler or host Python dependency installation is needed. The source-only test helper was verified with 170 passing unit tests, with a dependency deprecation warning. See [the testing guide](docs/TESTING.md) for scope and troubleshooting; passing tests are not a general accuracy percentage.

## Configuration and operations

| Setting | Purpose |
| --- | --- |
| `FWX_HOST_STORAGE` | Absolute host directory for inputs and job artifacts |
| `FWX_SANDBOX_UID`, `FWX_SANDBOX_GID` | Normal host user's IDs for mounted storage |
| `FWX_HTTP_PORT` | Loopback HTTP port; default 8000 |
| `FWX_COMPANY_REGISTRATION_CODE` | Shared registration code; keep private |
| `FWX_API_TOKEN` | Private credential for API automation |
| `FWX_SESSION_COOKIE_SECURE` | Enable secure cookies for HTTPS deployments |
| `FWX_MENTOR_AUTHORIZED_EXECUTION` | Legacy-named bounded vendor-execution switch |

Bootstrap also generates database credentials. Do not change database passwords in `.env` without coordinating the existing PostgreSQL roles. Do not move an existing installation without updating its absolute storage path.

```sh
docker compose ps
docker compose logs --tail=80 api migrate dispatcher
docker compose down
```

Stopping without `-v` retains database/queue volumes and local input storage. Do not run `down -v` unless you intentionally want to delete persisted data.

## Deployment

For a dedicated internal server, use [the deployment guide](docs/DEPLOYMENT.md): host prerequisites, HTTPS reverse proxy, trusted forwarding headers, secure sessions, restart policies, backups and upgrade steps. `compose.production.yaml` supplies operational settings, not a claim of complete production readiness.

The default binds only to localhost. Do not expose the raw HTTP API directly. This architecture requires Docker control and persistent storage; a basic hosted web-service plan alone cannot run the complete analysis backend.

## Repository contents

```text
src/         application, UI and analysis code
migrations/  database migrations
infra/       container build files and proxy example
locks/       pinned dependency hashes
fixtures/    controlled fixture source and analysis manifests
scripts/     setup, fixture-building and analysis utilities
tests/       regression test source
docs/        deployment and testing instructions
```

Generated reports, PDFs, screenshots, recordings, downloaded firmware, account databases, caches and private configuration are not part of the current source tree. Earlier commits may still contain previously published documents; this cleanup does not rewrite Git history.

## Licence

Apache-2.0 for this repository. Third-party tools and firmware retain their own licences.
