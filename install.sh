#!/bin/bash

echo "[*] Installing InsightLog..."

sudo mkdir -p /opt/InsightLog
sudo cp -r . /opt/InsightLog

cd /opt/InsightLog

echo "[*] Creating virtual environment..."
sudo python3 -m venv venv

echo "[*] Installing dependencies..."
sudo ./venv/bin/pip install -r requirements.txt

echo "[*] Installing systemd service..."
sudo cp insightlog.service /etc/systemd/system/

echo "[*] Reloading systemd..."
sudo systemctl daemon-reload

echo "[*] Enabling service..."
sudo systemctl enable insightlog

echo "[*] Starting service..."
sudo systemctl start insightlog

echo "[✓] Installation complete."