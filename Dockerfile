FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY shodan_monitor/ ./shodan_monitor
COPY scripts/ ./scripts

ENV PYTHONPATH=/app

CMD ["python", "/app/scripts/run_collector.py"]




