#!/usr/bin/env bash
# Spin up DVWA on localhost:4280
set -euo pipefail

if docker ps --format '{{.Names}}' | grep -q '^dvwa$'; then
    echo "DVWA container already running"
    exit 0
fi

docker run --rm -d --name dvwa -p 4280:80 vulnerables/web-dvwa >/dev/null
echo "DVWA started on http://localhost:4280"

# Wait for the container to accept HTTP requests
for i in {1..30}; do
    if curl -sf -o /dev/null http://localhost:4280/; then
        echo "DVWA ready"
        exit 0
    fi
    sleep 1
done

echo "DVWA failed to come up" >&2
exit 1
