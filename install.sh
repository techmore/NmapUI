#!/bin/bash

# NmapUI Installation Script
# This script installs all dependencies for NmapUI

set -e

echo "🚀 Installing NmapUI dependencies..."
echo "=================================="

# Check if running on macOS
if [[ "$OSTYPE" != "darwin"* ]]; then
    echo "⚠️  This script is optimized for macOS. For Linux/Ubuntu, see manual instructions below."
fi

# Check Python 3
echo "📦 Checking Python 3..."
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found. Please install Python 3 first."
    echo "   macOS: brew install python3"
    echo "   Ubuntu: sudo apt install python3 python3-pip python3-venv"
    exit 1
else
    echo "✅ Python 3 found: $(python3 --version)"
fi

# Create virtual environment
echo "📦 Creating Python virtual environment..."
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
    echo "✅ Virtual environment created"
else
    echo "✅ Virtual environment already exists"
fi

# Activate virtual environment
echo "📦 Activating virtual environment..."
source .venv/bin/activate
PLAYWRIGHT_BROWSERS_PATH="$(pwd)/.playwright-browsers"
export PLAYWRIGHT_BROWSERS_PATH

# Upgrade pip
echo "📦 Upgrading pip..."
pip install --upgrade pip

# Install Python dependencies
echo "📦 Installing Python dependencies..."
pip install -r requirements.txt
echo "✅ Python dependencies installed"

# Install the preferred browser payload for HTML-to-PDF rendering
echo "📦 Installing Playwright Chromium browser..."
python -m playwright install chromium
echo "✅ Playwright Chromium installed at $PLAYWRIGHT_BROWSERS_PATH"

# Check and install system dependencies
echo "📦 Checking system dependencies..."

# Check nmap
if ! command -v nmap &> /dev/null; then
    echo "📦 Installing nmap..."
    if command -v brew &> /dev/null; then
        brew install nmap
    else
        echo "❌ Please install nmap manually:"
        echo "   macOS: brew install nmap"
        echo "   Ubuntu: sudo apt install nmap"
        exit 1
    fi
else
    echo "✅ nmap found: $(nmap --version | head -1)"
fi

# Check arp-scan (optional)
if ! command -v arp-scan &> /dev/null; then
    echo "📦 Installing arp-scan (optional for MAC/vendor detection)..."
    if command -v brew &> /dev/null; then
        brew install arp-scan
    else
        echo "⚠️  arp-scan not found. Install manually for MAC/vendor detection:"
        echo "   Ubuntu: sudo apt install arp-scan"
    fi
else
    echo "✅ arp-scan found: $(arp-scan --version | head -1)"
fi

# Check browser/PDF tooling for report fallbacks
echo "📦 Checking browser/PDF tooling..."
if command -v google-chrome &> /dev/null || command -v /Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome &> /dev/null; then
    echo "✅ Chrome found (usable by Playwright/browser-based tooling if needed)"
else
    echo "⚠️  Chrome not found. Browser-based PDF fallbacks may be limited."
    echo "   Report generation still works with wkhtmltopdf or other configured tooling."
fi

# Check git (for vulners script)
if ! command -v git &> /dev/null; then
    echo "❌ Git not found. Please install Git:"
    echo "   macOS: brew install git"
    echo "   Ubuntu: sudo apt install git"
    exit 1
else
    echo "✅ Git found: $(git --version)"
fi

# Create startup script
echo "📦 Creating startup script..."
cat > start.sh << 'EOF'
#!/bin/bash
# NmapUI Startup Script

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Activate virtual environment
source "$ROOT_DIR/.venv/bin/activate"
export PLAYWRIGHT_BROWSERS_PATH="$ROOT_DIR/.playwright-browsers"

# Run the application
python app.py "$@"
EOF

chmod +x start.sh
echo "✅ Startup script created: ./start.sh"

echo ""
echo "🎉 Installation complete!"
echo "========================"
echo ""
echo "To start NmapUI:"
echo "  ./start.sh"
echo ""
echo "Or manually:"
echo "  source .venv/bin/activate"
echo "  python app.py"
echo ""
echo "Then visit: http://127.0.0.1:9000"
echo ""
echo "Optional: Use --quick flag to skip dependency checks:"
echo "  ./start.sh --quick"
echo ""
