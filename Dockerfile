FROM python:3.12-slim

WORKDIR /app
COPY auditor.py config.json ./
COPY engine/ ./engine/

EXPOSE 8080
ENTRYPOINT ["python3", "auditor.py"]
CMD ["--config", "config.json", "--web"]
