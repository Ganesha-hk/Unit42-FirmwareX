FROM python@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY locks/control.txt locks/otel-linux-x86_64.txt /app/locks/
RUN pip install --no-cache-dir --require-hashes -r locks/control.txt -r locks/otel-linux-x86_64.txt && pip check
COPY src /app/src
COPY pyproject.toml alembic.ini /app/
COPY migrations /app/migrations
ENV PYTHONPATH=/app/src
CMD ["uvicorn", "firmwarex.api:app", "--host", "0.0.0.0", "--port", "8000"]
