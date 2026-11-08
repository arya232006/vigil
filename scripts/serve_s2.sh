#!/usr/bin/env bash
# Serve the fine-tuned System-2 model (OpenAI-compatible) on :8090 for the backend.
set -euo pipefail
cd "$(dirname "$0")/.."
exec .venv/bin/python -m mlx_lm server --model ml/models/qwen3-1.7b-4bit --adapter-path "${ADAPTER:-ml/adapters/final}" \
  --host 127.0.0.1 --port "${S2_PORT:-8090}" --chat-template-args '{"enable_thinking":false}' --max-tokens 512
