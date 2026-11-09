#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../backend"
if [[ -f ../.env ]]; then set -a; source ../.env; set +a; fi
# Localhost only by default. To serve other machines set HOST, ALLOWED_HOSTS and CORS_ORIGINS (see README).
# A virtualenv inside an iCloud-synced folder can hang, so one outside the repo is preferred when present.
VENV="${VIGIL_VENV:-$HOME/.venvs/vigil}"
[[ -x "$VENV/bin/uvicorn" ]] || VENV=../.venv
exec "$VENV/bin/uvicorn" app.main:app --host "${HOST:-127.0.0.1}" --port "${PORT:-8000}" --no-server-header
