FROM firmwarex-fixtures:day1
RUN apt-get update && apt-get install -y --no-install-recommends libc6-dev libc6-dev-mips-cross libc6-dev-mipsel-cross libc6-dev-armel-cross libc6-dev-arm64-cross && rm -rf /var/lib/apt/lists/*
