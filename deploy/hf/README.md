---
title: Vigil
emoji: 🛡️
colorFrom: indigo
colorTo: gray
sdk: docker
app_port: 7860
pinned: false
license: apache-2.0
short_description: Self-hosted AI + cybersecurity threat investigation API
---

# Vigil API

Backend for **Vigil**: AI-powered web threat detection and digital trust intelligence.

- Analyse a URL, domain, message or email: `POST /api/analyze`, `POST /api/jobs`, `POST /api/analyze/email`
- Interactive API docs: `/docs` · health and model status: `/api/health` · model metrics: `/api/models`

The AI runs inside this Space: **vigil-s2** (Qwen3-1.7B + our LoRA fine-tune, GGUF Q8_0, served by llama.cpp) plus
our System-1 classifiers. No third-party AI service is called.

Deployed automatically from the project's GitHub repository (`backend/` + `deploy/hf/`).
