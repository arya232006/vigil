#!/usr/bin/env bash
# Package the fine-tuned System-2 model for hosting anywhere (Linux/cloud) via Ollama.
#   1. fuse LoRA adapter into the base weights (dequantized safetensors)
#   2. import into Ollama with int4 quantization  →  model "vigil-s2" (~1.7 GB)
# Serve it on a server with:  ollama serve  → backend env: S2_BASE_URL=http://<host>:11434/v1 S2_MODEL=vigil-s2
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="${OUT:-ml/export/vigil-s2-fused}"
.venv/bin/python -m mlx_lm fuse --model ml/models/qwen3-1.7b-4bit --adapter-path "${ADAPTER:-ml/adapters/final}" --save-path "$OUT" --dequantize
cat > ml/export/Modelfile <<MF
FROM $(pwd)/$OUT
PARAMETER temperature 0
PARAMETER num_ctx 4096
MF
ollama create vigil-s2 -f ml/export/Modelfile --quantize int4
ollama list | grep vigil-s2
