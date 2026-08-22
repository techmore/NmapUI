#!/bin/bash
# NmapUI Startup Script

# Activate virtual environment
source .venv/bin/activate

# Run the application
python app.py "$@"
