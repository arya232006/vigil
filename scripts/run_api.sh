#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../backend"
if [[ -f ../.env ]]; then set -a; source ../.env; set +a; fi
exec ../.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8000}"
