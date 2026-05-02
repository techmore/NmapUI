#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "========================================"
echo "TM-NMapUI - Dependency Installer"
echo "========================================"

BREW_PACKAGES=(
    "node"
    "nmap"
    "libxslt"
)

OPTIONAL_BREW_PACKAGES=(
    "wkhtmltopdf"
)

echo ""
echo "[1/5] Checking for Homebrew..."
if ! command -v brew &> /dev/null; then
    echo "Homebrew not found. Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
else
    echo "Homebrew found."
fi

echo ""
echo "[2/5] Updating Homebrew..."
brew update

echo ""
echo "[3/5] Installing system packages with Homebrew..."
for pkg in "${BREW_PACKAGES[@]}"; do
    if brew list "$pkg" &> /dev/null; then
        echo "$pkg already installed."
    else
        echo "Installing $pkg..."
        brew install "$pkg"
    fi
done

for pkg in "${OPTIONAL_BREW_PACKAGES[@]}"; do
    if brew list "$pkg" &> /dev/null; then
        echo "$pkg already installed."
    else
        echo "Installing optional package $pkg..."
        if ! brew install "$pkg"; then
            echo "WARNING: optional package $pkg is unavailable. PDF export can still use Chromium/Chrome when installed."
        fi
    fi
done

echo ""
echo "[4/5] Installing npm packages..."
if [ -f "package.json" ]; then
    if command -v npm &> /dev/null; then
        if [ -f "package-lock.json" ]; then
            npm ci
        else
            npm install
        fi
        echo "npm packages installed."
    else
        echo "ERROR: npm not found. Please install Node.js via Homebrew: brew install node"
        exit 1
    fi
else
    echo "WARNING: package.json not found. Skipping npm install."
fi

echo ""
echo "[5/5] Verifying installations..."
verify_commands=(
    "node:node"
    "npm:npm"
    "nmap:nmap"
    "python3:python3"
    "xsltproc:xsltproc"
    "express:node"
)

MISSING=0
for cmd in "${verify_commands[@]}"; do
    BINARY="${cmd%%:*}"
    CHECK_CMD="${cmd##*:}"
    if [[ "$BINARY" == "express" ]]; then
        if ! node -e "require('express')" &> /dev/null; then
            echo "MISSING: express"
            echo "Expected Express under: $(npm root 2>/dev/null || echo "$SCRIPT_DIR/node_modules")"
            echo "Try re-running ./install.sh from $SCRIPT_DIR"
            MISSING=1
        else
            echo "OK: express - installed"
        fi
    elif ! command -v "$CHECK_CMD" &> /dev/null; then
        echo "MISSING: $BINARY"
        MISSING=1
    else
        VERSION=$($CHECK_CMD --version 2>&1 | head -n1 || echo "installed")
        echo "OK: $BINARY - $VERSION"
    fi
done

echo ""
echo "========================================"
if [ $MISSING -eq 0 ]; then
    echo "Installation complete!"
    echo "Run 'sudo npm start' to start the application."
else
    echo "Some dependencies are missing."
    echo "Please restart your terminal and re-run this script."
    exit 1
fi
echo "========================================"
