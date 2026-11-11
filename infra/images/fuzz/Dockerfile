FROM firmwarex-pipeline:task5
RUN apt-get update && apt-get install -y --no-install-recommends gdb-multiarch && rm -rf /var/lib/apt/lists/*
COPY src /app/src
COPY fixtures/manifests/fuzz-controlled.json /app/fuzz-controlled.json
ENTRYPOINT ["python", "-m", "firmwarex.fuzz.runner"]
