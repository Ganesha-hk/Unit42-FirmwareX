FROM python@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258
COPY locks/analysis-linux-x86_64.txt /requirements.txt
RUN pip install --no-cache-dir --require-hashes -r /requirements.txt
