FROM python:3.12-slim

RUN useradd --system --create-home --home-dir /var/lib/homelab-auditor auditor \
    && mkdir -p /app /var/lib/homelab-auditor \
    && chown -R auditor:auditor /app /var/lib/homelab-auditor

WORKDIR /app
COPY --chown=auditor:auditor auditor.py config.json ./
COPY --chown=auditor:auditor engine/ ./engine/

USER auditor
EXPOSE 8080
ENTRYPOINT ["python3", "auditor.py"]
CMD ["--config", "config.json", "--db", "/var/lib/homelab-auditor/auditor_state.db", "--web"]
