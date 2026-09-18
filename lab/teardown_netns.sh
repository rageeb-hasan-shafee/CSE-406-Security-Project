#!/usr/bin/env bash
# Tears down everything lab/setup_netns.sh created. Safe to re-run.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "[!] Run as root (sudo)." >&2
    exit 1
fi

for ns in wscale-client wscale-server wscale-attacker; do
    if ip netns list 2>/dev/null | grep -q "$ns"; then
        ip netns del "$ns"
        echo "[*] removed namespace $ns"
    fi
done

if ip link show wscale-br0 &>/dev/null; then
    ip link del wscale-br0
    echo "[*] removed bridge wscale-br0"
fi

echo "[*] Lab torn down."
