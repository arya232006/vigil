"""Deploy the Vigil backend to its Hugging Face Docker Space.

Uploads only what the Space needs (backend/ + deploy/hf/*), so the frontend, contracts and ML training code stay out.
Run locally (uses your `hf auth login` token) or from the GitHub Action (uses the HF_TOKEN repository secret).

  python scripts/deploy_hf.py            # deploy code
  python scripts/deploy_hf.py --init     # first time: create the Space and set its HF_TOKEN secret (for the private model)
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from huggingface_hub import HfApi, get_token

ROOT = Path(__file__).resolve().parents[1]
SPACE = os.getenv("HF_SPACE", "aryadeep232006/vigil")
EXCLUDE = shutil.ignore_patterns("__pycache__", "*.pyc", "data", "Dockerfile", ".pytest_cache")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--init", action="store_true", help="create the Space and set the HF_TOKEN secret")
    a = ap.parse_args()
    token = os.getenv("HF_TOKEN") or get_token()
    if not token:
        raise SystemExit("No Hugging Face token: run `hf auth login` or set HF_TOKEN")
    api = HfApi(token=token)

    if a.init:
        api.create_repo(SPACE, repo_type="space", space_sdk="docker", exist_ok=True, private=False)
        api.add_space_secret(SPACE, "HF_TOKEN", token, description="downloads the private vigil-s2 model")

    stage = Path(tempfile.mkdtemp(prefix="vigil-space-"))
    shutil.copytree(ROOT / "backend", stage / "backend", ignore=EXCLUDE)
    shutil.copytree(ROOT / "backend" / "app" / "data", stage / "backend" / "app" / "data")   # feeds + datasets
    for f in ("Dockerfile", "README.md", "start.sh"):
        shutil.copy(ROOT / "deploy" / "hf" / f, stage / f)

    try:
        sha = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    except OSError:
        sha = "local"
    info = api.upload_folder(repo_id=SPACE, repo_type="space", folder_path=stage,
                             commit_message=f"Deploy backend from GitHub {sha or 'local'}",
                             delete_patterns=["backend/**"])
    print(f"Deployed to https://huggingface.co/spaces/{SPACE} ({info.oid[:8] if hasattr(info, 'oid') else 'ok'})")
    print(f"API: https://{SPACE.replace('/', '-').lower()}.hf.space")


if __name__ == "__main__":
    main()
