FROM python@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
# Debian snapshot fixes the native tool package universe for reproducible builds.
RUN rm -f /etc/apt/sources.list.d/debian.sources && printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20261001T000000Z bookworm main\n' > /etc/apt/sources.list \
 && apt-get update && apt-get install -y --no-install-recommends binwalk squashfs-tools util-linux e2fsprogs libarchive-tools mtd-utils cpio file \
 && rm -rf /var/lib/apt/lists/*
COPY locks/extract-linux-x86_64.txt /app/locks/extract-linux-x86_64.txt
RUN pip install --no-cache-dir --require-hashes -r /app/locks/extract-linux-x86_64.txt
COPY src /app/src
ENV PYTHONPATH=/app/src HOME=/tmp
ENTRYPOINT ["python", "-m", "firmwarex.runner"]
