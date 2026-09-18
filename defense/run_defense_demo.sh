#!/usr/bin/env bash
# Runs the SAME desync attack pipeline as measure/run_attack.sh, but with one defense
# active first, to test whether that defense actually detects or blocks the attack.
#
# Usage: sudo bash defense/run_defense_demo.sh arp|ipsec|ids
#   arp   -- static ARP entries: attacker should never get on-path at all
#   ipsec -- IPsec AH transport mode: tampered SYNs should be rejected/dropped
#   ids   -- live_ids.py watching an otherwise-undefended attack, to show detection
#            (IDS is a detect-only complement to arp/ipsec, not a blocking mechanism,
#            so it is deliberately tested without those defenses active)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTDIR="$ROOT/captures/defense"
mkdir -p "$OUTDIR"

if [[ $EUID -ne 0 ]]; then
    echo "[!] Run as root (sudo)." >&2
    exit 1
fi

MODE="${1:?usage: run_defense_demo.sh arp|ipsec|ids}"

stop_background() {
    pkill -TERM -f "attacker/arp_spoof.py" 2>/dev/null || true
    sleep 1
    pkill -9 -f "attacker/arp_spoof.py" 2>/dev/null || true
    pkill -9 -f "attacker/wscale_attack.py" 2>/dev/null || true
    pkill -9 -f "tcpdump -i wscale-br0" 2>/dev/null || true
    pkill -9 -f "defense/live_ids.py" 2>/dev/null || true
    sleep 0.5
}
trap 'stop_background; ip netns exec wscale-attacker bash "$ROOT/attacker/divert_rules.sh" teardown 2>/dev/null || true' EXIT

run_attack_pipeline() {
    local tag="$1"
    ip netns exec wscale-attacker sysctl -w net.ipv4.ip_forward=1 >/dev/null
    ip netns exec wscale-attacker sysctl -w net.ipv4.conf.all.send_redirects=0 >/dev/null
    ip netns exec wscale-attacker sysctl -w net.ipv4.conf.eth0.send_redirects=0 >/dev/null
    ip netns exec wscale-attacker sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
    ip netns exec wscale-attacker sysctl -w net.ipv4.conf.eth0.rp_filter=0 >/dev/null 2>&1 || true
    ip netns exec wscale-attacker bash "$ROOT/attacker/divert_rules.sh" setup

    ip netns exec wscale-attacker python3 "$ROOT/attacker/arp_spoof.py" \
        --iface eth0 --client-ip 10.0.0.1 --server-ip 10.0.0.2 &
    sleep 2
    ip netns exec wscale-attacker python3 "$ROOT/attacker/wscale_attack.py" \
        --queue-num 0 --new-shift 0 --target client-syn --client-ip 10.0.0.1 \
        >"$OUTDIR/${tag}_wscale_attack.log" 2>&1 &
    sleep 1
    tcpdump -i wscale-br0 -w "$OUTDIR/${tag}.pcap" -U -c 2000 &
    sleep 1

    ip netns exec wscale-server python3 "$ROOT/throughput/bulk_server.py" \
        --host 0.0.0.0 --port 9000 --once --stats-out "$OUTDIR/${tag}_server_stats.json" &
    sleep 1
    echo "[*] Attempting transfer (10s timeout -- if a defense blocks the connection,"
    echo "    timing out here IS the expected/successful result, not a script failure)"
    timeout 10 ip netns exec wscale-client python3 "$ROOT/throughput/bulk_client.py" \
        --host 10.0.0.2 --port 9000 --stats-out "$OUTDIR/${tag}_client_stats.json" \
        || echo "[*] Transfer did not complete within 10s"

    stop_background
    ip netns exec wscale-attacker bash "$ROOT/attacker/divert_rules.sh" teardown 2>/dev/null || true

    echo "[*] --- wscale_attack.py rewrite log ($tag) ---"
    cat "$OUTDIR/${tag}_wscale_attack.log" 2>/dev/null || true
    echo "[*] ---------------------------------------"
    python3 "$ROOT/analysis/detect_wscale_mismatch.py" "$OUTDIR/${tag}.pcap" || true
}

case "$MODE" in
  arp)
    echo "=== Defense test: static ARP entries ==="
    bash "$ROOT/defense/harden_arp.sh" apply
    run_attack_pipeline "arp_defense"
    bash "$ROOT/defense/harden_arp.sh" remove
    ;;
  ipsec)
    echo "=== Defense test: IPsec AH transport mode ==="
    bash "$ROOT/defense/setup_ipsec_ah.sh" apply
    run_attack_pipeline "ipsec_defense"
    bash "$ROOT/defense/setup_ipsec_ah.sh" remove
    ;;
  ids)
    echo "=== Defense test: live IDS detector watching an UNDEFENDED attack ==="
    python3 "$ROOT/defense/live_ids.py" --iface wscale-br0 >"$OUTDIR/ids_alerts.log" 2>&1 &
    IDS_PID=$!
    sleep 1
    run_attack_pipeline "ids_undefended"
    kill "$IDS_PID" 2>/dev/null || true
    sleep 1
    echo "[*] --- live_ids.py alerts ---"
    cat "$OUTDIR/ids_alerts.log" 2>/dev/null || true
    ;;
  *)
    echo "unknown mode: $MODE (expected arp|ipsec|ids)" >&2
    exit 1
    ;;
esac
