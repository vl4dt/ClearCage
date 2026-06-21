#!/bin/bash
set -e

# Start DinD daemon if not already running
if ! docker info >/dev/null 2>&1; then
    echo "Starting Docker-in-Docker daemon..."
    dockerd &
    # Wait for socket to be ready
    until docker info >/dev/null 2>&1; do
        echo "Waiting for Docker daemon..."
        sleep 2
    done
    echo "Docker daemon ready."
fi

# Pull analysis images (pre-warm DinD registry)
echo "Pulling analysis container images..."
docker pull remnux/yara:latest 2>/dev/null || true
docker pull remnux/pefile:latest 2>/dev/null || true
docker pull remnux/remnux-distro:noble 2>/dev/null || true

# Start FastAPI
echo "Starting ClearCage backend..."
exec uvicorn src.main:app --host 0.0.0.0 --port 8000 --log-level info
