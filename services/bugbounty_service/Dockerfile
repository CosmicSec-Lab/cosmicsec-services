FROM python:3.13-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements/ /app/requirements/
RUN pip install --no-cache-dir -r /app/requirements/runtime.txt

COPY services/bugbounty_service /app/services/bugbounty_service
COPY services/common /app/services/common
COPY cosmicsec_platform /app/cosmicsec_platform

RUN useradd -m -u 1000 cosmicsec && chown -R cosmicsec:cosmicsec /app
USER cosmicsec

EXPOSE 8009

HEALTHCHECK --interval=15s --timeout=5s --retries=6 --start-period=20s \
    CMD curl -fsS http://localhost:8009/health || exit 1

CMD ["uvicorn", "services.bugbounty_service.main:app", "--host", "0.0.0.0", "--port", "8009"]
