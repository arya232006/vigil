# Vigil API + self-hosted vigil-s2 model, as one Hugging Face Docker Space.
#   llama.cpp's official server image serves the GGUF model (OpenAI-compatible, logprobs, chat_template_kwargs);
#   a uv-managed Python 3.13 venv runs the FastAPI backend. Spaces run containers as uid 1000.
FROM ghcr.io/ggml-org/llama.cpp:server

USER root
ENTRYPOINT []
COPY --from=ghcr.io/astral-sh/uv:0.5.11 /uv /usr/local/bin/uv

ENV UV_PYTHON_INSTALL_DIR=/opt/python UV_CACHE_DIR=/tmp/uv-cache
RUN uv venv --python 3.13 /opt/venv

WORKDIR /home/vigil/app
COPY backend/requirements.txt backend/requirements.txt
RUN uv pip install --python /opt/venv/bin/python --no-cache -r backend/requirements.txt "huggingface_hub>=0.30" \
    && rm -rf /tmp/uv-cache

COPY --chown=1000:1000 backend backend
COPY --chown=1000:1000 start.sh start.sh
RUN mkdir -p /home/vigil && chown -R 1000:1000 /home/vigil

USER 1000
ENV HOME=/home/vigil \
    PATH=/opt/venv/bin:$PATH \
    LD_LIBRARY_PATH=/app \
    DB_PATH=/tmp/vigil/reports.db \
    S2_BASE_URL=http://127.0.0.1:8090/v1 \
    S2_MODEL=vigil-s2 \
    S2_TIMEOUT=150 \
    OLLAMA_URL=http://127.0.0.1:9 \
    TRUST_PROXY=1 \
    MODEL_REPO=aryadeep232006/vigil-s2-gguf \
    MODEL_FILE=vigil-s2-Q8_0.gguf

EXPOSE 7860
CMD ["sh", "start.sh"]
