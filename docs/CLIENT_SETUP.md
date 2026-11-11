# Run FirmwareX on another computer

The repository includes the application source, browser assets, Docker build files, pinned Python dependencies, database migrations, analysis manifests, fixture source, configuration generator and startup/test helpers. It does not need files from the developer's home directory.

## Before cloning

Use Linux x86-64, or an Ubuntu x86-64 VM on Windows/macOS. Native Windows/macOS and ARM hosts have not been validated. Install Git, Python 3, Docker Engine and Docker Compose v2. Your normal user must be able to run `docker info`; Docker membership is administrative access to the host. Do not run the setup using sudo.

Allow internet access for Docker/package downloads and any public firmware you choose to download. The pinned base images and package sources must remain available. The project does not include Docker Engine, a preconfigured virtual machine or offline dependency archives.

## First run

```sh
git clone https://github.com/Ganesha-hk/Unit42-FirmwareX.git
cd Unit42-FirmwareX
python3 scripts/check-setup.py
sh scripts/start.sh
```

If GitHub asks for authentication, the owner must give the client access to this private repository. No developer credentials are supplied with the checkout.

The first startup builds all required application/analysis images, creates a new private `.env`, creates storage under `.runtime`, applies database migrations and starts services. Keep the checkout path stable after setup because `FWX_HOST_STORAGE` records an absolute path.

Open `http://127.0.0.1:8000/` inside the host/VM where Docker runs. Read `FWX_COMPANY_REGISTRATION_CODE` privately from `.env`, register an employee, then log in with that employee ID and password. Never reuse or ask for the developer's company code, database password or API token.

## Try an image

Use a licensed firmware image or run `python3 scripts/fetch-corpus.py` to download the manifest's public OpenWrt images. They are checksum-verified and saved in `work/corpus/`. The root README explains the tested OpenWrt input, upload form and bounded-execution switch.

The default leaves vendor-image execution disabled. A client must deliberately enable that switch on a suitable isolated host before expecting the selected real-image emulation and symbolic stages to run. Unknown firmware may still be incomplete. A setting cannot supply missing hardware/library support.

## Verify and operate

```sh
sh scripts/test.sh
docker compose ps
docker compose logs --tail=80 api migrate dispatcher
docker compose down
sh scripts/start.sh --no-build
```

The test helper compiles its own fixture inputs from repository source. Existing developer fixture binaries are not needed. It does not automatically upload or execute real firmware.

`down` keeps persistent volumes. Do not use `down -v` unless you intend to erase data. Do not copy a live database or share `.env` to prepare an installation for another client.

## Updates and production

For a local installation, save work and make a backup, pull the intended revision, and rerun `sh scripts/start.sh` to rebuild images and recreate changed services. Do not pull over local edits without reviewing them. Schema migrations need a rollback/backup plan.

For client access over a domain, follow [DEPLOYMENT.md](DEPLOYMENT.md) before exposing the service. The default URL is loopback-only, not a shareable public site. DNS, valid TLS certificates, proxy configuration, backups and server access are client/operator responsibilities. The included production override cannot provide those automatically.

This repository provides a reproducible setup route; it does not claim every client environment has already been tested or that the application's documented production limitations are resolved.
