FROM python:3.12-slim

WORKDIR /app

# Security: non-root user
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser

# System deps for chromadb (requires native libs for sentence-transformers)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p logs && chown -R appuser:appgroup /app

USER appuser

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2", "--loop", "uvloop"]
