# Task 2 validation record

This is the foundation/static milestone, not final FirmwareX acceptance.

## Verified behavior

- Isolated Python 3.12.15; locked control dependencies install and pip check passes.
- angr 10.0.4.post1, Unicorn 2.1.4 and solver run in isolated Python 3.12. Controlled ELF CFG: 33 functions; solver satisfiable; controlled Unicorn NOP succeeds. Initial missing-UID-name failure fixed by USER/HOME environment for the smoke run.
- 13 unit tests pass: compiler hardening variants, shared-library PIE distinction, inventory/limits/symlink handling, entropy/signature, malformed ELF and cross-compiled MIPS/MIPSEL/ARM32/ARM64 metadata.
- Three real API/queue/PostgreSQL/offline-container scenarios pass: SquashFS, custom header plus gzip, unsupported input. No target executable is run.
- Five additional controlled format scenarios pass: CramFS, JFFS2, UBIFS, cpio and ext.
- Frozen OpenWrt 24.10.4 corpus: 6/6 extraction successes, covering x86_64, ARM32, ARM64, MIPS, MIPSEL; SquashFS and ext4. Full inventory and mitigation matrices recorded. This is 100% on the declared corpus, not a claim of all-vendor/general extraction success.
- Three controlled hardening variants match checksec on NX, PIE, RELRO, canary, FORTIFY and stripped status.
- Auth/missing-ID/invalid-UUID API guards pass.
- Database runtime role cannot update/delete/truncate audit events; uploaded/started/finished lifecycle events exist.
- Static profile probe confirms nonroot UID, zero effective capabilities, loopback-only network, no default route, no Docker socket and read-only root paths. This is not the Day 2 complete packet/quota/escape proof or mentor sign-off.

## Evidence

All in evidence/day1: unit-tests-final.log, unit-tests.xml, unit-coverage.xml, api-integration.json, api-integration-final.log, format-integration.json, format-integration-final.log, corpus-results.json, corpus-validation-retry.log, checksec-comparison.json, runtime-smoke-retry.log, api-guards.json, database-verification.json, static-profile-probe.json, image-ids.txt and manifests/extraction-packages.txt.

Failed attempts are retained: packaging failed when an unnecessary editable install lacked setuptools; removed that install because PYTHONPATH loads application sources. Initial root-with-dropped-capabilities test could not write reports; rerun as UID 1000 succeeded. Binwalk needed HOME=/tmp. CramFS/Jefferson require nonexistent output directories. SquashFS device inodes are now metadata-only, never materialized. These failures were not counted as passes.

## Reproduction commands

```sh
docker build -f infra/images/fixtures.Dockerfile -t firmwarex-fixtures:day1 .
docker run --rm --network none --user 1000:1000 --cap-drop ALL --security-opt no-new-privileges -v "$PWD/work/fixtures:/fixtures" -v "$PWD/scripts/build-format-fixtures.sh:/build.sh:ro" firmwarex-fixtures:day1 sh /build.sh
python3 scripts/verify-formats.py

docker run --rm --network none --user 1000:1000 --cap-drop ALL --security-opt no-new-privileges --memory 512m -w /tmp -v "$PWD/src:/app/src:ro" -v "$PWD/tests:/app/tests:ro" -v "$PWD/work/fixtures:/fixtures:ro" -v "$PWD/evidence/day1:/evidence" firmwarex-control:day1 pytest /app/tests/unit -q --cov=firmwarex.static --cov=firmwarex.inventory --cov=firmwarex.extract --cov-report=xml:/evidence/unit-coverage.xml --junitxml=/evidence/unit-tests.xml

docker compose exec -T api python < scripts/verify-database.py
docker build -f infra/images/analysis/Dockerfile -t firmwarex-analysis-runtime:day1 .
docker run --rm --network none --user 1000:1000 -e USER=firmwarex -e HOME=/tmp --cap-drop ALL --security-opt no-new-privileges --memory 1g --pids-limit 64 -v "$PWD/work/fixtures:/fixtures:ro" -v "$PWD/scripts/runtime-smoke.py:/smoke.py:ro" firmwarex-analysis-runtime:day1 python /smoke.py
```

Cross-architecture fixture recipe: use matching cross gcc from the fixture image with -nostdlib -shared -fPIC on fixtures/sources/cross.c. No cross-built binary is executed.

## Important remaining work

No full containment/quota-breach acceptance yet; no redaction/fingerprint scanner; no OpenTelemetry; no dynamic emulation, taint or fuzzing product; no normalized finding/report/dashboard; no final performance target tested. Running-job recovery after dispatcher death and stronger queue back-pressure tests remain. Output fields are not yet protected by the Day 3 universal sanitizer; keep API local and use only authorized inputs.

No mentor review or PR has occurred. The corpus is a frozen project baseline requiring reviewer agreement as the final “standard set.” Original PRD four-week scope is not finished by this milestone.

## Task 2 completion follow-up

The static engineering follow-up is complete and all executed regression checks pass. Human review has not been substituted with an automated result.

Additional evidence under evidence/task2-completion/: quotas.json (actual production launcher with controlled CPU/memory/wall breaches and cleanup), recovery-admission.json (orphan recovery, immutable recovery audit, 16-job admission limit and responsive health), clean-migration.log and migration-downgrade/upgrade.log (isolated fresh database), three dependency-license inventories, and final unit/API/formats/corpus regressions.

The network probe uses the production network-none profile: host TCP connect fails ENETUNREACH; IPv4/IPv6 UDP sends to reserved documentation addresses fail without a route; only loopback exists; mount is EPERM and no Docker socket is present. This validates the static profile only, not the future contained service-network architecture or a general kernel-escape claim.

The frozen migration no longer imports evolving application models. Docker stats now uses one-shot sampling; recorded wall duration includes the complete workload. Dead dispatcher recovery runs after a 300-second lease, kills/removes matching labeled orphans, marks the job dispatcher_lost, and audits it. It does not fabricate a successful result or silently rerun an abandoned job.

Final regressions: 13 unit tests, three API scenarios, five additional filesystem scenarios, six of six corpus images; all pass. Quota tests: wall, CPU and memory breach each terminated; cleanup verified. Admission test returned 429 and health 200. No untrusted firmware emulation, push or PR occurred.

Remaining Task 2 human workflow: PR review and mentor unpacking review; agreement that the declared six-image corpus is the acceptance baseline. The PRD §15 requires review; these are not engineering failures and cannot be self-approved. Separate future-stage requirements (redaction, telemetry, QEMU, symbolic/taint, reporting/UI) remain open according to the five-day plan.
