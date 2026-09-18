#!/usr/bin/env bash
# Implementation Plan step 1 ("Lab setup"): capture a clean handshake + throughput run
# before any tampering, so later runs have something to compare against.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTDIR="$ROOT/captures/baseline"
mkdir -p "$OUTDIR"

if [[ $EUID -ne 0 ]]; then
    echo "[!] Run as root (sudo)." >&2
    exit 1
fi

echo "[*] Capturing baseline handshake + transfer on wscale-br0"
tcpdump -i wscale-br0 -w "$OUTDIR/handshake.pcap" -U -c 2000 &
TCPDUMP_PID=$!
sleep 1

ip netns exec wscale-server python3 "$ROOT/throughput/bulk_server.py" \
    --host 0.0.0.0 --port 9000 --once --stats-out "$OUTDIR/server_stats.json" &
SERVER_PID=$!
sleep 1

ip netns exec wscale-client python3 "$ROOT/throughput/bulk_client.py" \
    --host 10.0.0.2 --port 9000 --stats-out "$OUTDIR/client_stats.json"

wait "$SERVER_PID" 2>/dev/null || true
kill "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true

echo "[*] Baseline complete. Results in $OUTDIR"
python3 "$ROOT/measure/compare.py" --baseline-dir "$OUTDIR" --show-only baseline
