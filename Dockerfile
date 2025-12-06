# Multi-stage Dockerfile for the Python microservice

# Stage 1: Builder
FROM python:3.11-slim AS builder
ENV PIP_NO_CACHE_DIR=1
WORKDIR /app

# Install build deps required to build wheels for cryptography
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       build-essential \
       libssl-dev \
       libffi-dev \
       ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency manifest early for caching
COPY requirements.txt ./

# Install Python deps into /install prefix
RUN pip install --upgrade pip setuptools wheel \
    && pip install --prefix=/install -r requirements.txt \
    && rm -rf /root/.cache/pip


# Stage 2: Runtime
FROM python:3.11-slim
ENV TZ=UTC
ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /app

# Install runtime system packages (cron, tzdata)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       cron \
       tzdata \
       ca-certificates \
       procps \
    && ln -snf /usr/share/zoneinfo/UTC /etc/localtime \
    && echo UTC > /etc/timezone \
    && rm -rf /var/lib/apt/lists/*

# Copy installed Python packages from builder
COPY --from=builder /install /install
ENV PYTHONPATH=/install/lib/python3.11/site-packages
ENV PATH=/install/bin:$PATH

# Copy application code
COPY . /app

# Ensure scripts are executable
RUN chmod +x /app/scripts/*.py || true

# Install cron job
COPY cron/2fa-cron /etc/cron.d/2fa-cron
RUN chmod 0644 /etc/cron.d/2fa-cron \
    && touch /var/log/cron.log

# Create volumes and set permissions
RUN mkdir -p /data /cron \
    && chmod 0755 /data /cron

# Expose application port
EXPOSE 8080

# Start cron and the API server
CMD ["/bin/sh", "-c", "cron && uvicorn src.api:app --host 0.0.0.0 --port 8080"]
