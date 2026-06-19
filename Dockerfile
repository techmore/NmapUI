FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    NMAPUI_DATA_DIR=/data \
    NMAPUI_LOG_DIR=/data/logs \
    NMAPUI_HOST=0.0.0.0 \
    NMAPUI_PORT=9000

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    arp-scan \
    git \
    nmap \
    procps \
    traceroute \
    xsltproc \
    wkhtmltopdf \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt

RUN pip install --upgrade pip \
    && pip install -r requirements.txt \
    && python -m playwright install --with-deps chromium

COPY . /app

RUN mkdir -p /data /data/logs

EXPOSE 9000

CMD ["python", "app.py"]
