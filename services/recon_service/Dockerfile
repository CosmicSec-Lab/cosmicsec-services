FROM python:3.13-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements/ /app/requirements/
RUN pip install --no-cache-dir -r /app/requirements/runtime.txt

COPY services/recon_service /app/services/recon_service
COPY services/common /app/services/common
COPY cosmicsec_platform /app/cosmicsec_platform

RUN useradd -m -u 1000 cosmicsec && chown -R cosmicsec:cosmicsec /app
USER cosmicsec

EXPOSE 8004

CMD ["uvicorn", "services.recon_service.main:app", "--host", "0.0.0.0", "--port", "8004"]
