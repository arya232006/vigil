"""Vigil backend on Modal: the vigil-s2 model on a GPU (llama.cpp) + the FastAPI API.

Deploy:   .venv/bin/modal deploy deploy/modal/vigil_modal.py
Secrets (create once, values never in code):
  vigil-hf       HF_TOKEN            read access to the private model repo
  vigil-backend  CHAIN_PRIVATE_KEY   the Sepolia wallet that anchors reports (use any placeholder key=value to run without anchoring)
"""
import os
from pathlib import Path

import modal

ROOT = Path(__file__).resolve().parents[2] if modal.is_local() else Path("/root")   # repo root, only needed to build
MODEL_REPO = "aryadeep232006/vigil-s2-gguf"
MODEL_FILE = "vigil-s2-Q8_0.gguf"
GPU_WARM = int(os.environ.get("VIGIL_GPU_WARM", "0"))   # VIGIL_GPU_WARM=1 modal deploy ... keeps one GPU up (judging)

app = modal.App("vigil")
model_cache = modal.Volume.from_name("vigil-models", create_if_missing=True)

# ---------------------------------------------------------------- vigil-s2 on a GPU ----------
llama_image = (
    modal.Image.from_registry("ghcr.io/ggml-org/llama.cpp:server-cuda", add_python="3.12")
    .entrypoint([])
    .pip_install("huggingface_hub>=0.30")
    .env({"LD_LIBRARY_PATH": "/app:/usr/local/cuda/lib64:/usr/local/nvidia/lib64"})
)


@app.function(image=llama_image, gpu=["L4", "A10G", "T4", "L40S"],   # first one with capacity
              volumes={"/models": model_cache},
              secrets=[modal.Secret.from_name("vigil-hf")], min_containers=GPU_WARM, scaledown_window=600,
              timeout=3600)
@modal.concurrent(max_inputs=8)
@modal.web_server(port=8080, startup_timeout=900)
def model():
    import os
    import subprocess

    from huggingface_hub import hf_hub_download

    path = hf_hub_download(MODEL_REPO, MODEL_FILE, local_dir="/models", token=os.environ["HF_TOKEN"])
    model_cache.commit()
    subprocess.Popen(["/app/llama-server", "-m", path, "--host", "0.0.0.0", "--port", "8080", "--jinja",
                      "--alias", "vigil-s2", "-c", "16384", "-np", "4", "--temp", "0", "-ngl", "99"])


# ---------------------------------------------------------------- FastAPI backend -------------
api_image = (
    modal.Image.debian_slim(python_version="3.13")
    .pip_install_from_requirements(str(ROOT / "backend" / "requirements.txt"))
    .env({
        "DB_PATH": "/tmp/vigil/reports.db",       # one instance; resets on restart (anchors stay on-chain)
        "S2_MODEL": "vigil-s2",
        "S2_TIMEOUT": "150",                      # covers a GPU cold start
        "OLLAMA_URL": "http://127.0.0.1:9",       # no local fallback model here: template fallback
        "TRUST_PROXY": "1",
        "ALLOWED_HOSTS": "koe-labs--vigil-api.us-east.modal.run",
        "CORS_ORIGINS": "https://vigil.arddev.in",   # also checked against the Clerk token azp claim
        "CHAIN_RPC_URL": "https://ethereum-sepolia-rpc.publicnode.com",
        "CHAIN_CONTRACT_ADDRESS": "0x012175dc68cb5480e37419a2ec9e04ee5Eef216F",
        "CHAIN_DEPLOY_BLOCK": "12095029",
        "CHAIN_TRUSTED_REPORTER": "0xc77944D7e8E9Fb1742ae75b538834E7f08c1Daf1",
        "CLERK_PUBLISHABLE_KEY": "pk_test_YWJvdmUtY2hhbW9pcy0zMDYyLmNsZXJrLmFjY291bnRzLmRldiQ",
    })
    .add_local_dir(str(ROOT / "backend"), "/root/backend",
                   ignore=["**/__pycache__/**", "data/**", ".pytest_cache/**", "Dockerfile"])
)


@app.function(image=api_image, secrets=[modal.Secret.from_name("vigil-backend")],
              cpu=2, memory=4096, min_containers=1, max_containers=1, timeout=600)
@modal.concurrent(max_inputs=50)
@modal.asgi_app()
def api():
    import sys

    os.environ.setdefault("S2_BASE_URL", model.get_web_url().rstrip("/") + "/v1")
    sys.path.insert(0, "/root/backend")
    from app.main import app as fastapi_app      # noqa: E402

    return fastapi_app
