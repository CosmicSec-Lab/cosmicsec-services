FROM python:3.13-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    curl \
    openssh-server \
    && rm -rf /var/lib/apt/lists/*

COPY requirements/ /app/requirements/
RUN pip install --no-cache-dir -r /app/requirements/runtime.txt

COPY services/admin_service /app/services/admin_service
COPY services/common /app/services/common
COPY cosmicsec_platform /app/cosmicsec_platform

RUN mkdir -p /run/sshd && useradd -m -u 1000 cosmicsec && chown -R cosmicsec:cosmicsec /app
USER cosmicsec

EXPOSE 8015 2222

HEALTHCHECK --interval=15s --timeout=5s --retries=6 --start-period=20s \
    CMD python -c "from services.admin_service.state import load_state; load_state()" || exit 1

ENTRYPOINT ["python", "-m", "services.admin_service.cli"]
