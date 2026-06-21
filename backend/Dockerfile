# ClearCage Backend — Python 3.12 + DinD
FROM docker:27-dind AS dind-base

# Runtime stage
FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="ClearCage"
LABEL org.opencontainers.image.description="Threat analysis platform backend"

WORKDIR /app

# System deps for analysis tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    tini \
    && rm -rf /var/lib/apt/lists/*

# Copy DinD binary from builder
COPY --from=dind-base /usr/local/bin/docker /usr/local/bin/docker

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code
COPY src/ ./src/

# Config (read-only, mounted at runtime)
# Volumes: yara-rules, samples, config

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONPATH=/app/src

EXPOSE 8000

ENTRYPOINT ["tini", "--"]
CMD ["/app/src/entrypoint.sh"]
