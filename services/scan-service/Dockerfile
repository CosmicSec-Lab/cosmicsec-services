FROM python:3.11-slim

WORKDIR /app

# Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY services/scan_service /app/services/scan_service

# Create non-root user
RUN useradd -m -u 1000 cosmicsec && chown -R cosmicsec:cosmicsec /app
USER cosmicsec

EXPOSE 8002

CMD ["uvicorn", "services.scan_service.main:app", "--host", "0.0.0.0", "--port", "8002"]
