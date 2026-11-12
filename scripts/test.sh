#!/bin/sh
# Compile controlled test fixtures inside Docker, then run unit tests offline.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
docker build -f infra/images/fixtures.Dockerfile -t firmwarex-fixtures:local .
docker build -f infra/images/control/Dockerfile -t firmwarex-control:day1 .
mkdir -p work/fixtures
docker run --rm --network none --user "$(id -u):$(id -g)" \
    -e PYTHONDONTWRITEBYTECODE=1 -v "$PWD:/project:ro" \
    -v "$PWD/work/fixtures:/project/work/fixtures" \
    -v "$PWD/work/fixtures:/fixtures" -v "$PWD/fixtures/sources:/sources:ro" \
    --entrypoint sh firmwarex-fixtures:local -ec '
        python /project/scripts/build-fixtures.py
        sh /project/scripts/build-cross-fixtures.sh
        as /sources/static-risk.s -o /tmp/static-risk.o
        ld -N /tmp/static-risk.o -o /fixtures/static-risk
    '
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
    --user "$(id -u):$(id -g)" -e PYTHONDONTWRITEBYTECODE=1 -e PYTHONPATH=/app/src \
    -v "$PWD/src:/app/src:ro" -v "$PWD/tests:/tests:ro" \
    -v "$PWD/work/fixtures:/fixtures:ro" --entrypoint python firmwarex-control:day1 \
    -m pytest /tests/unit -q -p no:cacheprovider
