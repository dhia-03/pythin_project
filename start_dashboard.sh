#!/bin/bash
# Quick start script for the IDS Dashboard

echo "========================================"
echo "   IDS Dashboard - Quick Start"
echo "========================================"
echo ""

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Error: Virtual environment not found!"
    echo "Run: python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt"
    exit 1
fi

# Activate virtual environment  
echo "[1/2] Activating virtual environment..."
source venv/bin/activate

# Start dashboard
echo "[2/2] Starting IDS Dashboard..."
echo ""
echo "Dashboard will be available at: http://localhost:5000"
echo "Default login: admin / admin123"
echo ""
echo "Press Ctrl+C to stop"
echo "========================================" 
echo ""

python app.py
