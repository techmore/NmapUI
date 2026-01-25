# NmapUI Go Edition - Deployment Guide

This guide covers production deployment of NmapUI Go Edition.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Running the Service](#running-the-service)
5. [Troubleshooting](#troubleshooting)
6. [Upgrading](#upgrading)
7. [Uninstallation](#uninstallation)

---

## Prerequisites

### System Requirements

**Minimum:**
- Linux (Ubuntu 20.04+, RHEL 8+, Debian 11+) or macOS 11+
- 1 CPU core
- 512 MB RAM
- 100 MB disk space

**Recommended:**
- 2+ CPU cores
- 1 GB RAM
- 1 GB disk space (for scan history)

### Required Software

1. **nmap** (required for scanning)
   ```bash
   # Ubuntu/Debian
   sudo apt install nmap
   
   # RHEL/CentOS
   sudo yum install nmap
   
   # macOS
   brew install nmap
   ```

2. **xsltproc** (required for report generation)
   ```bash
   # Ubuntu/Debian
   sudo apt install xsltproc
   
   # RHEL/CentOS
   sudo yum install libxslt
   
   # macOS
   brew install libxslt
   ```

3. **wkhtmltopdf** (optional, for PDF reports)
   ```bash
   # Ubuntu/Debian
   sudo apt install wkhtmltopdf
   
   # macOS
   brew install wkhtmltopdf
   ```

### Network Requirements

- **Port 9000** (default) must be available
- **Root privileges** required for SYN scans (`nmap -sS`)
  - Alternative: Run with Connect scans (`nmap -sT`, no root required)

---

## Installation

### Method 1: Automated Installation (Recommended)

```bash
# Clone repository
git clone https://github.com/techmore/NmapUI.git
cd NmapUI/go-nmapui

# Build binary
make build

# Install (requires sudo)
sudo ./scripts/install.sh
```

The installation script will:
- ✅ Copy binary to `/usr/local/bin/nmapui`
- ✅ Create directories: `/etc/nmapui`, `/var/lib/nmapui`, `/var/log/nmapui`
- ✅ Install systemd service file
- ✅ Copy configuration files
- ✅ Set proper permissions

### Method 2: Manual Installation

```bash
# Build binary
make build

# Copy binary
sudo cp bin/nmapui /usr/local/bin/nmapui
sudo chmod +x /usr/local/bin/nmapui

# Create directories
sudo mkdir -p /etc/nmapui
sudo mkdir -p /var/lib/nmapui
sudo mkdir -p /var/log/nmapui

# Copy configuration
sudo cp config/customers.yaml /etc/nmapui/customers.yaml

# Copy systemd service
sudo cp scripts/nmapui.service /etc/systemd/system/nmapui.service

# Reload systemd
sudo systemctl daemon-reload
```

### Method 3: Download Pre-built Binary

```bash
# Download latest release (replace VERSION with actual version)
VERSION=v1.0.0
ARCH=linux-amd64  # or darwin-amd64, darwin-arm64, windows-amd64.exe

wget https://github.com/techmore/NmapUI/releases/download/${VERSION}/nmapui-${ARCH}

# Make executable
chmod +x nmapui-${ARCH}

# Install
sudo mv nmapui-${ARCH} /usr/local/bin/nmapui
```

---

## Configuration

### Environment Variables

The service can be configured via environment variables:

```bash
# Server configuration
PORT=9000                                    # HTTP server port (default: 9000)
HOST=0.0.0.0                                 # Bind address (default: 0.0.0.0)

# Database configuration
DB_PATH=/var/lib/nmapui/nmapui.db           # SQLite database path

# Customer configuration
CUSTOMERS_YAML=/etc/nmapui/customers.yaml   # Customer fingerprint database

# Scanning configuration
MAX_CONCURRENT=10                            # Max concurrent scans (default: 10)
NMAP_PATH=nmap                               # Path to nmap binary

# Logging
LOG_LEVEL=info                               # Log level: debug, info, warn, error
```

### Systemd Service Configuration

Edit `/etc/systemd/system/nmapui.service`:

```ini
[Service]
# Set environment variables here
Environment="PORT=9000"
Environment="DB_PATH=/var/lib/nmapui/nmapui.db"
Environment="CUSTOMERS_YAML=/etc/nmapui/customers.yaml"
Environment="MAX_CONCURRENT=10"
```

### Customer Fingerprint Database

Edit `/etc/nmapui/customers.yaml` to add customer network fingerprints:

```yaml
customers:
  - id: customer-1
    name: "ACME Corporation"
    description: "Main office network"
    network_keys:
      - exit_ip: "203.0.113.1"
        hops:
          - hop: 1
            ip: "192.168.1.1"
          - hop: 2
            ip: "10.0.0.1"
          - hop: 3
            ip: "203.0.113.1"
        confidence: 0.95

  - id: customer-2
    name: "Example Inc"
    description: "Remote office"
    network_keys:
      - exit_ip: "198.51.100.1"
        hops:
          - hop: 1
            ip: "172.16.0.1"
          - hop: 2
            ip: "198.51.100.1"
        confidence: 0.90
```

### Firewall Configuration

**Ubuntu/Debian (ufw):**
```bash
sudo ufw allow 9000/tcp
sudo ufw reload
```

**RHEL/CentOS (firewalld):**
```bash
sudo firewall-cmd --permanent --add-port=9000/tcp
sudo firewall-cmd --reload
```

**macOS:**
No firewall configuration needed (macOS firewall allows outbound by default).

---

## Running the Service

### Start the Service

```bash
# Start service
sudo systemctl start nmapui

# Enable auto-start on boot
sudo systemctl enable nmapui

# Check status
sudo systemctl status nmapui
```

### View Logs

```bash
# Follow logs in real-time
sudo journalctl -u nmapui -f

# View recent logs
sudo journalctl -u nmapui -n 100

# View logs since boot
sudo journalctl -u nmapui -b
```

### Stop the Service

```bash
sudo systemctl stop nmapui
```

### Restart the Service

```bash
sudo systemctl restart nmapui
```

### Check Server Health

```bash
curl http://localhost:9000/api/health
# Expected output: {"status":"ok"}
```

---

## Troubleshooting

### Service Won't Start

**Check logs:**
```bash
sudo journalctl -u nmapui -n 50
```

**Common issues:**

1. **Port already in use**
   ```
   Error: bind: address already in use
   ```
   Solution: Change port in service file or kill process using port 9000
   ```bash
   sudo lsof -i :9000
   sudo kill <PID>
   ```

2. **Permission denied**
   ```
   Error: permission denied
   ```
   Solution: Service must run as root for SYN scans
   ```bash
   # Verify User=root in /etc/systemd/system/nmapui.service
   ```

3. **nmap not found**
   ```
   Error: nmap binary not found
   ```
   Solution: Install nmap
   ```bash
   sudo apt install nmap  # Ubuntu/Debian
   sudo yum install nmap  # RHEL/CentOS
   ```

### Database Issues

**Reset database:**
```bash
sudo systemctl stop nmapui
sudo rm /var/lib/nmapui/nmapui.db
sudo systemctl start nmapui
```

**Check database permissions:**
```bash
sudo ls -la /var/lib/nmapui/nmapui.db
# Should be owned by root:root with 644 permissions
```

### Scan Failures

**Check nmap installation:**
```bash
which nmap
nmap --version
```

**Test manual scan:**
```bash
# Quick scan (no root required)
nmap -sn 127.0.0.1

# SYN scan (requires root)
sudo nmap -sS 127.0.0.1
```

**Verify network connectivity:**
```bash
ping 8.8.8.8
traceroute 8.8.8.8
```

### High Memory Usage

**Check current memory usage:**
```bash
ps aux | grep nmapui
```

**Reduce concurrent scans:**
```bash
# Edit service file
sudo nano /etc/systemd/system/nmapui.service

# Change MAX_CONCURRENT to lower value
Environment="MAX_CONCURRENT=5"

# Restart service
sudo systemctl daemon-reload
sudo systemctl restart nmapui
```

### WebSocket Connection Issues

**Check server is listening:**
```bash
sudo netstat -tlnp | grep 9000
```

**Test WebSocket connection:**
```bash
# Open test_websocket.html in browser
# Should see "Connected" status
```

**Check for reverse proxy issues:**
If using nginx/apache, ensure WebSocket upgrade headers are forwarded:
```nginx
location / {
    proxy_pass http://localhost:9000;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
}
```

---

## Upgrading

### Method 1: Automated Upgrade

```bash
# Stop service
sudo systemctl stop nmapui

# Backup database
sudo cp /var/lib/nmapui/nmapui.db /var/lib/nmapui/nmapui.db.backup

# Download new version
cd /path/to/NmapUI/go-nmapui
git pull
make build

# Reinstall
sudo ./scripts/install.sh

# Start service
sudo systemctl start nmapui
```

### Method 2: Manual Upgrade

```bash
# Stop service
sudo systemctl stop nmapui

# Backup database
sudo cp /var/lib/nmapui/nmapui.db /var/lib/nmapui/nmapui.db.backup

# Replace binary
sudo cp bin/nmapui /usr/local/bin/nmapui

# Restart service
sudo systemctl start nmapui
```

### Rollback

```bash
# Stop service
sudo systemctl stop nmapui

# Restore binary
sudo cp /usr/local/bin/nmapui.old /usr/local/bin/nmapui

# Restore database
sudo cp /var/lib/nmapui/nmapui.db.backup /var/lib/nmapui/nmapui.db

# Start service
sudo systemctl start nmapui
```

---

## Uninstallation

```bash
# Stop and disable service
sudo systemctl stop nmapui
sudo systemctl disable nmapui

# Remove service file
sudo rm /etc/systemd/system/nmapui.service
sudo systemctl daemon-reload

# Remove binary
sudo rm /usr/local/bin/nmapui

# Remove configuration (optional)
sudo rm -rf /etc/nmapui

# Remove data (optional - contains scan history)
sudo rm -rf /var/lib/nmapui

# Remove logs (optional)
sudo rm -rf /var/log/nmapui
```

---

## Security Considerations

### Running Without Root

For environments where root access is not allowed:

```bash
# Use Connect scans instead of SYN scans
# Connect scans don't require root but are slower and more detectable

# Edit service file
Environment="SCAN_TYPE=connect"
```

### Network Isolation

For maximum security, run NmapUI on an isolated management network:

```bash
# Bind to specific interface only
Environment="HOST=192.168.1.100"  # Management network only
```

### HTTPS/TLS

NmapUI does not include built-in HTTPS. Use a reverse proxy:

```nginx
server {
    listen 443 ssl;
    server_name scanner.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:9000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

---

## Performance Tuning

### Increase Concurrent Scans

```bash
# Edit service file
Environment="MAX_CONCURRENT=20"
```

### Database Optimization

The SQLite database uses WAL mode by default for better concurrency. No tuning needed.

### Resource Limits

```bash
# Edit service file to increase limits
[Service]
LimitNOFILE=65535
LimitNPROC=512
```

---

## Backup and Recovery

### Backup Database

```bash
# Manual backup
sudo cp /var/lib/nmapui/nmapui.db /backup/nmapui-$(date +%Y%m%d).db

# Automated backup (cron)
0 2 * * * cp /var/lib/nmapui/nmapui.db /backup/nmapui-$(date +\%Y\%m\%d).db
```

### Backup Configuration

```bash
sudo cp /etc/nmapui/customers.yaml /backup/customers-$(date +%Y%m%d).yaml
```

### Restore from Backup

```bash
sudo systemctl stop nmapui
sudo cp /backup/nmapui-20260125.db /var/lib/nmapui/nmapui.db
sudo cp /backup/customers-20260125.yaml /etc/nmapui/customers.yaml
sudo systemctl start nmapui
```

---

## Support

- **Documentation:** https://github.com/techmore/NmapUI
- **Issues:** https://github.com/techmore/NmapUI/issues
- **Discussions:** https://github.com/techmore/NmapUI/discussions

---

## License

MIT License - see LICENSE file
