#!/bin/bash
set -e

# NmapUI Go Edition - Installation Script
# Requires root privileges

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/nmapui"
DATA_DIR="/var/lib/nmapui"
LOG_DIR="/var/log/nmapui"
SERVICE_NAME="nmapui"
BINARY_NAME="nmapui"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    log_error "This script must be run as root"
    exit 1
fi

# Check if systemd is available
if ! command -v systemctl &> /dev/null; then
    log_error "systemd is required but not found"
    exit 1
fi

# Check if nmap is installed
if ! command -v nmap &> /dev/null; then
    log_error "nmap is required but not installed"
    log_info "Install with: apt-get install nmap (Debian/Ubuntu) or yum install nmap (RHEL/CentOS)"
    exit 1
fi

# Check if binary exists
if [ ! -f "./bin/${BINARY_NAME}" ]; then
    log_error "Binary not found at ./bin/${BINARY_NAME}"
    log_info "Run 'make build' first to create the binary"
    exit 1
fi

log_info "Starting NmapUI installation..."

# Stop existing service if running
if systemctl is-active --quiet ${SERVICE_NAME}; then
    log_info "Stopping existing ${SERVICE_NAME} service..."
    systemctl stop ${SERVICE_NAME}
fi

# Create directories
log_info "Creating directories..."
mkdir -p ${CONFIG_DIR}
mkdir -p ${DATA_DIR}
mkdir -p ${LOG_DIR}

# Install binary
log_info "Installing binary to ${INSTALL_DIR}/${BINARY_NAME}..."
cp "./bin/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
chmod +x "${INSTALL_DIR}/${BINARY_NAME}"

# Install configuration files
log_info "Installing configuration files..."
if [ -f "./config/customers.yaml" ]; then
    cp "./config/customers.yaml" "${CONFIG_DIR}/customers.yaml"
    chmod 644 "${CONFIG_DIR}/customers.yaml"
else
    log_warn "customers.yaml not found, creating empty file"
    touch "${CONFIG_DIR}/customers.yaml"
    chmod 644 "${CONFIG_DIR}/customers.yaml"
fi

# Copy web assets if they exist
if [ -d "./web" ]; then
    log_info "Installing web assets..."
    cp -r ./web "${DATA_DIR}/"
    chmod -R 755 "${DATA_DIR}/web"
fi

# Copy nmap-vulners if it exists
if [ -d "./nmap-vulners" ]; then
    log_info "Installing nmap-vulners scripts..."
    cp -r ./nmap-vulners "${DATA_DIR}/"
    chmod -R 755 "${DATA_DIR}/nmap-vulners"
fi

# Install systemd service
log_info "Installing systemd service..."
if [ -f "./scripts/nmapui.service" ]; then
    cp "./scripts/nmapui.service" "/etc/systemd/system/${SERVICE_NAME}.service"
    chmod 644 "/etc/systemd/system/${SERVICE_NAME}.service"
else
    log_error "Service file not found at ./scripts/nmapui.service"
    exit 1
fi

# Reload systemd
log_info "Reloading systemd daemon..."
systemctl daemon-reload

# Enable service
log_info "Enabling ${SERVICE_NAME} service..."
systemctl enable ${SERVICE_NAME}

# Set permissions
log_info "Setting permissions..."
chown -R root:root ${CONFIG_DIR}
chown -R root:root ${DATA_DIR}
chown -R root:root ${LOG_DIR}

log_info "${GREEN}Installation complete!${NC}"
echo ""
log_info "Next steps:"
echo "  1. Edit configuration: ${CONFIG_DIR}/customers.yaml"
echo "  2. Start service: systemctl start ${SERVICE_NAME}"
echo "  3. Check status: systemctl status ${SERVICE_NAME}"
echo "  4. View logs: journalctl -u ${SERVICE_NAME} -f"
echo "  5. Access UI: http://localhost:9000"
echo ""
log_info "Firewall configuration (if needed):"
echo "  firewall-cmd --permanent --add-port=9000/tcp"
echo "  firewall-cmd --reload"
echo ""
log_warn "Remember: NmapUI requires root privileges for SYN scans (-sS)"
