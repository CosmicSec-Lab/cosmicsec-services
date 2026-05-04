FROM python:3.13-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements/ /app/requirements/
RUN pip install --no-cache-dir -r /app/requirements/runtime.txt

COPY services/egress_service /app/services/egress_service
COPY services/common /app/services/common
COPY cosmicsec_platform /app/cosmicsec_platform

RUN useradd -m -u 1000 cosmicsec && chown -R cosmicsec:cosmicsec /app
USER cosmicsec

EXPOSE 8016

HEALTHCHECK --interval=15s --timeout=5s --retries=6 --start-period=20s \
    CMD curl -fsS http://localhost:8016/health || exit 1

CMD ["uvicorn", "services.egress_service.main:app", "--host", "0.0.0.0", "--port", "8016"]
