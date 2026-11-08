"""Shared test setup: runs before any test module imports the app.
Isolated temp database + AI layer pointed at a dead port (template fallback, no GPU/model calls)."""
import os
import sys
import tempfile
from pathlib import Path

_TMP = Path(tempfile.mkdtemp(prefix="threatscope-tests-"))
os.environ["DB_PATH"] = str(_TMP / "reports.db")
os.environ["S2_BASE_URL"] = "http://127.0.0.1:9/v1"
os.environ["OLLAMA_URL"] = "http://127.0.0.1:9"
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
