# Trusted test observer only. Never an analysis worker.
FROM firmwarex-native:day1
RUN apt-get update && apt-get install -y --no-install-recommends tcpdump && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["tcpdump"]
