# Vigil backend (API + System-1 models). System-2 runs as a separate OpenAI-compatible server:
#  - Apple Silicon: scripts/serve_s2.sh (MLX)
#  - Linux/cloud: llama.cpp `llama-server -m vigil-s2.gguf --port 8090` (see docs/ARCHITECTURE.md)
FROM python:3.12-slim
WORKDIR /app
RUN useradd -m appuser
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
ENV DB_PATH=/data/reports.db S2_BASE_URL=http://host.docker.internal:8090/v1 PORT=8000
RUN mkdir -p /data && chown appuser /data
USER appuser
EXPOSE 8000
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT}"]
