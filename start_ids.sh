#!/bin/bash
# Quick start script for the IDS Engine (requires root)

echo "========================================"
echo "   IDS Detection Engine - Quick Start"
echo "========================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root (sudo)"
    echo "Run: sudo ./start_ids.sh"
    exit 1
fi

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Error: Virtual environment not found!"
    exit 1
fi

echo "[1/2] Activating virtual environment..."
echo "[2/2] Starting IDS Detection Engine..."
echo ""
echo "Monitoring network traffic..."
echo "Port scan threshold: 5 unique ports"
echo ""
echo "Test with: nmap -p 1-20 localhost"
echo "Press Ctrl+C to stop"
echo "========================================" 
echo ""

./venv/bin/python Integration.py
