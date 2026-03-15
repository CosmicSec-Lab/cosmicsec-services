FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY services/ai_service /app/services/ai_service

RUN useradd -m -u 1000 cosmicsec && chown -R cosmicsec:cosmicsec /app
USER cosmicsec

EXPOSE 8003

CMD ["uvicorn", "services.ai_service.main:app", "--host", "0.0.0.0", "--port", "8003"]
