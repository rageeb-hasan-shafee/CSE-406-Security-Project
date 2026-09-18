#!/usr/bin/env bash
# Defense: "Stop the MITM" (deck, Defense Ideas). Installs static/PERMANENT ARP
# (neighbor) entries on the client and server, each pinned to the other's REAL MAC
# address. Linux's kernel does not update a PERMANENT neighbor-table entry in response
# to unsolicited ARP traffic, so attacker/arp_spoof.py's forged replies have no effect
# once this is applied. This is a single-host stand-in for switch-level Dynamic ARP
# Inspection / static ARP entries, which the lab has no real managed switch to provide.
#
# Usage (run in the host namespace, as root):
#   sudo bash defense/harden_arp.sh apply
#   sudo bash defense/harden_arp.sh remove
set -euo pipefail
ACTION="${1:?usage: harden_arp.sh apply|remove}"

if [[ $EUID -ne 0 ]]; then
    echo "[!] Run as root (sudo)." >&2
    exit 1
fi

CLIENT_IP=10.0.0.1
SERVER_IP=10.0.0.2

if [[ "$ACTION" == "apply" ]]; then
    CLIENT_MAC=$(ip netns exec wscale-client cat /sys/class/net/eth0/address)
    SERVER_MAC=$(ip netns exec wscale-server cat /sys/class/net/eth0/address)
    echo "[*] client real MAC = $CLIENT_MAC"
    echo "[*] server real MAC = $SERVER_MAC"

    ip netns exec wscale-client ip neigh replace "$SERVER_IP" lladdr "$SERVER_MAC" dev eth0 nud permanent
    ip netns exec wscale-server ip neigh replace "$CLIENT_IP" lladdr "$CLIENT_MAC" dev eth0 nud permanent

    echo "[*] Static (permanent) ARP entries installed on client and server."
    ip netns exec wscale-client ip neigh show "$SERVER_IP"
    ip netns exec wscale-server ip neigh show "$CLIENT_IP"

elif [[ "$ACTION" == "remove" ]]; then
    ip netns exec wscale-client ip neigh del "$SERVER_IP" dev eth0 2>/dev/null || true
    ip netns exec wscale-server ip neigh del "$CLIENT_IP" dev eth0 2>/dev/null || true
    echo "[*] Static ARP entries removed (back to normal dynamic ARP)."
else
    echo "unknown action: $ACTION" >&2
    exit 1
fi
