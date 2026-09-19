#!/usr/bin/env bash

set -e

echo "=========================================="
echo " TCP Window Scaling Attack - Setup"
echo "=========================================="

# Must be run from project root
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

echo
echo "[1/4] Installing system dependencies..."

sudo apt-get update

sudo apt-get install -y \
    iproute2 \
    iptables \
    tcpdump \
    python3 \
    python3-pip \
    python3-venv \
    build-essential \
    python3-dev \
    libnetfilter-queue-dev \
    dsniff \
    slowhttptest

echo
echo "[2/4] Creating Python virtual environment..."

if [ ! -d ".venv" ]; then
    python3 -m venv .venv
else
    echo "[*] .venv already exists. Reusing it."
fi

echo
echo "[3/4] Installing Python dependencies..."

source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -r requirements.txt

echo
echo "[4/4] Verifying installation..."

python - <<'PY'
from scapy.all import IP, TCP
from netfilterqueue import NetfilterQueue

print("[+] Scapy: OK")
print("[+] NetfilterQueue: OK")
print("[+] Python dependencies: OK")
PY

echo
echo "=========================================="
echo " Setup completed successfully!"
echo "=========================================="
echo
echo "Activate the environment with:"
echo
echo "    source .venv/bin/activate"
echo
echo "Then create the lab topology with:"
echo
echo "    sudo bash lab/setup_netns.sh"
echo
