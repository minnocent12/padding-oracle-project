FROM python:3.10-slim

WORKDIR /app

# Install dependencies first (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all phase code
COPY phase1/ ./phase1/
COPY phase2/ ./phase2/
COPY phase3/ ./phase3/
COPY phase4/ ./phase4/
