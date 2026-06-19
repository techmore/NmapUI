FROM node:20-bookworm-slim

ENV NODE_ENV=production \
    NMAPUI_DATA_DIR=/data \
    PORT=9000

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    chromium \
    curl \
    lsof \
    net-tools \
    nmap \
    python3 \
    traceroute \
    wkhtmltopdf \
    xsltproc \
    && rm -rf /var/lib/apt/lists/*

COPY package*.json /app/
RUN npm ci --omit=dev

COPY . /app

RUN mkdir -p /data/reports_archive /data/work \
    && useradd --system --create-home --home-dir /home/nmapui nmapui \
    && chown -R nmapui:nmapui /app /data

USER nmapui

EXPOSE 9000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:9000/api/app-identity >/dev/null || exit 1

CMD ["node", "server.js"]
