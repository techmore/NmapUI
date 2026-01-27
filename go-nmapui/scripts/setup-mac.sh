#!/bin/bash
set -e

# NmapUI Go Edition - macOS Setup Script
# Run this script before using NmapUI on a fresh Mac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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

log_step() {
    echo -e "\n${BLUE}==>${NC} ${1}"
}

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║           NmapUI Go Edition - macOS Setup                 ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# Check if running on macOS
if [[ "$(uname)" != "Darwin" ]]; then
    log_error "This script is for macOS only"
    log_info "For Linux, use: scripts/install.sh"
    exit 1
fi

# =============================================================================
# Step 1: Install Homebrew (if not installed)
# =============================================================================
log_step "Checking Homebrew..."

if ! command -v brew &> /dev/null; then
    log_warn "Homebrew not found. Installing..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

    # Add Homebrew to PATH for Apple Silicon Macs
    if [[ -f "/opt/homebrew/bin/brew" ]]; then
        eval "$(/opt/homebrew/bin/brew shellenv)"
        echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
    fi
    log_info "Homebrew installed successfully"
else
    log_info "Homebrew is already installed"
    brew update
fi

# =============================================================================
# Step 2: Install Go (for building from source)
# =============================================================================
log_step "Checking Go..."

if ! command -v go &> /dev/null; then
    log_warn "Go not found. Installing..."
    brew install go
    log_info "Go installed successfully"
else
    GO_VERSION=$(go version | awk '{print $3}')
    log_info "Go is already installed ($GO_VERSION)"
fi

# =============================================================================
# Step 3: Install nmap
# =============================================================================
log_step "Checking nmap..."

if ! command -v nmap &> /dev/null; then
    log_warn "nmap not found. Installing..."
    brew install nmap
    log_info "nmap installed successfully"
else
    NMAP_VERSION=$(nmap --version | head -1)
    log_info "nmap is already installed ($NMAP_VERSION)"
fi

# =============================================================================
# Step 4: Install arp-scan
# =============================================================================
log_step "Checking arp-scan..."

if ! command -v arp-scan &> /dev/null; then
    log_warn "arp-scan not found. Installing..."
    brew install arp-scan
    log_info "arp-scan installed successfully"
else
    ARP_VERSION=$(arp-scan --version 2>&1 | head -1)
    log_info "arp-scan is already installed ($ARP_VERSION)"
fi

# =============================================================================
# Step 5: Install nmap-vulners script (for CVE detection)
# =============================================================================
log_step "Checking nmap-vulners script..."

NMAP_SCRIPTS_DIR="/opt/homebrew/share/nmap/scripts"
if [[ ! -d "$NMAP_SCRIPTS_DIR" ]]; then
    NMAP_SCRIPTS_DIR="/usr/local/share/nmap/scripts"
fi

if [[ -f "$NMAP_SCRIPTS_DIR/vulners.nse" ]]; then
    log_info "nmap-vulners script is already installed"
else
    log_warn "Installing nmap-vulners script..."
    if [[ -d "$PROJECT_DIR/nmap-vulners" ]]; then
        sudo cp "$PROJECT_DIR/nmap-vulners/vulners.nse" "$NMAP_SCRIPTS_DIR/" 2>/dev/null || {
            log_warn "Could not copy vulners.nse to nmap scripts directory"
            log_info "CVE scanning may not work without vulners script"
        }
    else
        # Download from GitHub
        curl -sL "https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse" -o /tmp/vulners.nse
        sudo cp /tmp/vulners.nse "$NMAP_SCRIPTS_DIR/" 2>/dev/null || {
            log_warn "Could not install vulners.nse (may need sudo)"
        }
    fi

    # Update nmap script database
    sudo nmap --script-updatedb 2>/dev/null || true
    log_info "nmap-vulners script installed"
fi

# =============================================================================
# Step 6: Build the NmapUI binary
# =============================================================================
log_step "Building NmapUI..."

cd "$PROJECT_DIR"

# Download Go dependencies
log_info "Downloading Go dependencies..."
go mod download

# Build the binary
log_info "Compiling NmapUI..."
go build -o nmapui ./cmd/nmapui

if [[ -f "$PROJECT_DIR/nmapui" ]]; then
    BINARY_SIZE=$(ls -lh "$PROJECT_DIR/nmapui" | awk '{print $5}')
    log_info "Binary built successfully: $PROJECT_DIR/nmapui ($BINARY_SIZE)"
else
    log_error "Failed to build binary"
    exit 1
fi

# =============================================================================
# Step 7: Create necessary directories
# =============================================================================
log_step "Setting up directories..."

mkdir -p "$PROJECT_DIR/data/scans"
mkdir -p "$PROJECT_DIR/data/reports"
mkdir -p "$PROJECT_DIR/config"

# Create default customers.yaml if it doesn't exist
if [[ ! -f "$PROJECT_DIR/config/customers.yaml" ]]; then
    log_info "Creating default customers.yaml..."
    cat > "$PROJECT_DIR/config/customers.yaml" << 'YAML'
# NmapUI Customer Configuration
# Add your customers here for network fingerprinting

customers: []

# Example:
# customers:
#   - id: "acme-corp"
#     name: "ACME Corporation"
#     patterns:
#       - "10.0.0.*"
#       - "192.168.1.*"
#     confidence: 0.8
YAML
fi

log_info "Directories created"

# =============================================================================
# Step 8: Verify installation
# =============================================================================
log_step "Verifying installation..."

echo ""
echo "Checking installed components:"
echo "  - Homebrew: $(brew --version | head -1)"
echo "  - Go:       $(go version | awk '{print $3}')"
echo "  - nmap:     $(nmap --version | head -1 | awk '{print $3}')"
echo "  - arp-scan: $(arp-scan --version 2>&1 | head -1 | awk '{print $3}')"
echo "  - NmapUI:   $(ls -lh "$PROJECT_DIR/nmapui" | awk '{print $5}') binary"
echo ""

# =============================================================================
# Step 9: Optional - Create launch script
# =============================================================================
log_step "Creating launch script..."

cat > "$PROJECT_DIR/start-nmapui.sh" << 'SCRIPT'
#!/bin/bash
# Start NmapUI Go Edition
cd "$(dirname "$0")"
echo "Starting NmapUI on http://localhost:9000"
echo "Press Ctrl+C to stop"
echo ""
./nmapui
SCRIPT

chmod +x "$PROJECT_DIR/start-nmapui.sh"
log_info "Created start-nmapui.sh"

# =============================================================================
# Done!
# =============================================================================
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║              Setup Complete!                              ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "To start NmapUI:"
echo ""
echo "  cd $PROJECT_DIR"
echo "  ./start-nmapui.sh"
echo ""
echo "Or directly:"
echo ""
echo "  ./nmapui"
echo ""
echo "Then open http://localhost:9000 in your browser"
echo ""
log_warn "Note: Some scan types require root privileges. Run with sudo if needed:"
echo "  sudo ./nmapui"
echo ""
