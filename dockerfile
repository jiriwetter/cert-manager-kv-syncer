FROM python:3.11-slim

RUN useradd --create-home --shell /bin/bash appuser
USER appuser

WORKDIR /app

COPY --chown=appuser:appuser app/aks-kv-syncer.py app/requirements.txt /app/

RUN pip install --no-cache-dir -r requirements.txt

ENV PYTHONUNBUFFERED=1

RUN chmod 700 /app && chmod 600 /app/aks-kv-syncer.py /app/requirements.txt

ENTRYPOINT ["python", "sre-local-certificate-sync.py"]