FROM firmwarex-native:day1
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev binutils checksec gcc-mips-linux-gnu gcc-mipsel-linux-gnu gcc-arm-linux-gnueabi gcc-aarch64-linux-gnu libc6-dev-mips-cross libc6-dev-mipsel-cross libc6-dev-armel-cross libc6-dev-arm64-cross \
 && rm -rf /var/lib/apt/lists/*
