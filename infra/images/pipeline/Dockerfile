FROM firmwarex-qemu:task3
RUN apt-get update && apt-get install -y --no-install-recommends gdb-multiarch qemu-utils && rm -rf /var/lib/apt/lists/*
COPY locks/analysis-linux-x86_64.txt locks/otel-linux-x86_64.txt /locks/
RUN pip install --no-cache-dir --require-hashes -r /locks/analysis-linux-x86_64.txt -r /locks/otel-linux-x86_64.txt && pip check
COPY src /app/src
COPY fixtures/manifests/pipeline-controlled.json /app/pipeline-controlled.json
COPY fixtures/manifests/fuzz-controlled.json /app/fuzz-controlled.json
COPY fixtures/manifests/snapshot-controlled.json /app/snapshot-controlled.json
COPY fixtures/manifests/openwrt-24.10.4.json /app/openwrt-corpus.json
ENTRYPOINT ["python", "-m", "firmwarex.pipeline"]
