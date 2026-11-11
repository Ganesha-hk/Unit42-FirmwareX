FROM firmwarex-native:day1
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev binutils checksec gcc-mips-linux-gnu gcc-mipsel-linux-gnu gcc-arm-linux-gnueabi gcc-aarch64-linux-gnu \
 && rm -rf /var/lib/apt/lists/*
