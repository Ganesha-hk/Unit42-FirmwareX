# Tests and development

## Unit tests

Build the application using `sh scripts/start.sh`, then run:

```sh
sh scripts/test.sh
```

The test helper builds a compiler image, creates fixture files under ignored `work/fixtures/`, and runs pytest with networking disabled and fixture mounts read-only. Fixture building compiles test programs but does not execute firmware binaries. The tests include ELF inspection, output redaction, job budgets, scanner rules, symbolic model helpers and employee authentication/session behavior.

The full suite requires those fixture files. Missing `/fixtures/rootfs`, `/fixtures/cross` or `/fixtures/static-risk` causes fixture-dependent failures; do not treat a run without these inputs as a complete verification. The Python packages stay inside containers.

The authentication unit tests use an isolated test database and a test rate-store implementation. They do not replace real PostgreSQL/Redis/browser integration checks.

## Analysis-model checks

The source includes bounded symbolic allocation, environment and runtime-model verifiers in `scripts/verify-symbolic-*.py`. They require their corresponding compiled fixtures and the analysis dependencies. Inspect each script's expected paths before running it inside the pipeline image. Run fixture programs only in the defined sandbox or an appropriately isolated test container, not directly on the host.

The `fixtures/manifests/` files are execution/profile inputs, not saved assessment reports. Changing fixture sources may change binary hashes. Do not update a registration hash blindly to make a failing containment or profile check pass.

## Local changes

Rebuild the affected image after code changes, then recreate services. The container images copy application source at build time. Editing a host source file does not patch a running container automatically.

```sh
docker compose build api
docker compose up -d --force-recreate api dispatcher scheduler
```

If the analysis implementation changed, rebuild `firmwarex-pipeline:task5` as well. See `scripts/start.sh` for dependency order. Production deployments use both Compose files and the maintenance procedure in DEPLOYMENT.md.

## Results and limits

A passing unit suite checks the assertions in that suite. It does not prove every real-image vulnerability is detected, every reported candidate is valid, or sandboxing is invulnerable. The application must preserve incomplete/unsupported statuses and show the executed scope.

Keep generated logs and reports locally under ignored `evidence/`, `reports/` or `work/`. Do not commit credentials, account data, downloaded firmware or large recordings. This repository contains reproducible test source rather than historical output bundles.
