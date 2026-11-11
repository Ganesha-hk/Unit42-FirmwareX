FROM firmwarex-analysis-runtime:day1
COPY src /app/src
ENV PYTHONPATH=/app/src HOME=/tmp USER=firmwarex
ENTRYPOINT ["python", "-m", "firmwarex.analysis.runner"]
