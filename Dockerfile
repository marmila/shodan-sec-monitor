FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY shodan-monitor/ ./shodan-monitor
COPY scripts/ ./scripts

WORKDIR /app/scripts
CMD ["python", "run_collector.py"]

