FROM firmwarex-native:day1
RUN apt-get update && apt-get install -y --no-install-recommends qemu-user qemu-system-arm qemu-system-mips qemu-system-x86 && rm -rf /var/lib/apt/lists/*
COPY src /app/src
ENV PYTHONPATH=/app/src HOME=/tmp USER=firmwarex
ENTRYPOINT ["python", "-m", "firmwarex.emulation.runner"]
