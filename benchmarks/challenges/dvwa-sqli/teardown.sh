#!/usr/bin/env bash
set -euo pipefail
docker stop dvwa >/dev/null 2>&1 || true
