# AgentWall honeypot — stdlib only, so a slim base with no pip install needed.
FROM python:3.12-slim

WORKDIR /app
# only the files the honeypot needs at runtime
COPY honeypot.py events.py detectors.py ingest.py analyze.py correlation.py ./

# non-root
RUN useradd -r -u 10001 agentwall && mkdir -p /var/log/agentwall \
    && chown -R agentwall /var/log/agentwall
USER agentwall

EXPOSE 8899
# default: listen on all interfaces inside the container, trust the proxy in
# front of it (compose/k8s/CDN terminates TLS and sets X-Forwarded-For).
ENTRYPOINT ["python3", "honeypot.py"]
CMD ["--host", "0.0.0.0", "--port", "8899", \
     "--log", "/var/log/agentwall/honeypot.jsonl", "--trust-proxy"]
