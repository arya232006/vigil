#!/bin/sh
# Download the vigil-s2 GGUF (private model repo; HF_TOKEN is a Space secret), start llama-server, then the API.
set -e
mkdir -p /tmp/vigil /tmp/models

python - <<'PY'
import os
from huggingface_hub import hf_hub_download
path = hf_hub_download(os.environ["MODEL_REPO"], os.environ["MODEL_FILE"], local_dir="/tmp/models",
                       token=os.environ.get("HF_TOKEN"))
print("vigil-s2 model ready:", path, flush=True)
PY

/app/llama-server -m "/tmp/models/$MODEL_FILE" --host 127.0.0.1 --port 8090 --jinja \
    -c 8192 -np 2 --temp 0 -t "$(nproc)" > /tmp/vigil/llama-server.log 2>&1 &

cd backend
exec uvicorn app.main:app --host 0.0.0.0 --port 7860
