#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

export NMAPUI_DATA_DIR="${NMAPUI_DATA_DIR:-$HOME/Library/Application Support/NmapUI}"
export NMAPUI_RUNTIME_WORKDIR="${NMAPUI_RUNTIME_WORKDIR:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
export PORT="${PORT:-9000}"
export HOST="${HOST:-127.0.0.1}"

swift run
