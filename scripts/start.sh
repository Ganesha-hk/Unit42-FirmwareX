#!/bin/sh
# Build and start the local application without replacing existing credentials.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
case "${1:-}" in ''|--no-build) ;; *) echo 'Usage: sh scripts/start.sh [--no-build]' >&2; exit 2;; esac
command -v python3 >/dev/null
python3 scripts/check-setup.py
if [ ! -f .env ]; then python3 scripts/bootstrap.py; fi
if [ "${1:-}" != --no-build ]; then
    docker build -f infra/images/extract/Dockerfile -t firmwarex-native:day1 .
    docker tag firmwarex-native:day1 firmwarex-static:day1
    docker build -f infra/images/qemu/Dockerfile -t firmwarex-qemu:task3 .
    docker build -f infra/images/pipeline/Dockerfile -t firmwarex-pipeline:task5 .
    docker compose build api
else
    for image in firmwarex-native:day1 firmwarex-static:day1 firmwarex-qemu:task3 firmwarex-pipeline:task5 firmwarex-control:day1; do
        docker image inspect "$image" >/dev/null
    done
fi
docker compose up -d
python3 scripts/wait-ready.py
