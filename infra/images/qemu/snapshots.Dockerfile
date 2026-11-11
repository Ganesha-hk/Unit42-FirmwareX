FROM firmwarex-pipeline:task5
COPY src /app/src
COPY fixtures/manifests/snapshot-controlled.json /app/snapshot-controlled.json
ENTRYPOINT ["python", "-m", "firmwarex.emulation.snapshots"]
