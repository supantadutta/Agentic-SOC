FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /opt/agentic-soc

RUN useradd --system --create-home --uid 10001 agentic

COPY pyproject.toml README.md ./
COPY agentic_soc ./agentic_soc
COPY evaluation ./evaluation
RUN pip install ".[postgres,cloud]"

COPY config ./config
COPY scripts ./scripts
RUN mkdir -p /opt/agentic-soc/data /opt/agentic-soc/evidence && chown -R agentic /opt/agentic-soc/data /opt/agentic-soc/evidence

USER agentic
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz')"
CMD ["uvicorn", "--factory", "agentic_soc.api.app:app_factory", "--host", "0.0.0.0", "--port", "8000"]
