#!/usr/bin/env bash
# Fine-tune System-2 (Qwen3-1.7B 4-bit + LoRA) on the distilled dataset with MLX. ~20-40 min on Apple Silicon.
set -euo pipefail
cd "$(dirname "$0")/.."
ITERS="${ITERS:-700}"
.venv/bin/python -m mlx_lm lora \
  --model ml/models/qwen3-1.7b-4bit --train --data ml/data/s2 \
  --fine-tune-type lora --mask-prompt --num-layers 16 \
  --batch-size 8 --iters "$ITERS" --learning-rate 1e-4 --max-seq-length 1536 --grad-checkpoint \
  --steps-per-report 20 --steps-per-eval 100 --val-batches 8 --save-every 100 \
  --adapter-path ml/adapters/s2
