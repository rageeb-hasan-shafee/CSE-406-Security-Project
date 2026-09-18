#!/usr/bin/env bash
# Builds the 3-node topology from the "Network Topology & Components" slide using Linux
# network namespaces + a bridge as the switch, instead of real VMs:
#
#   [client netns] --veth--\
#                            (wscale-br0 bridge = "Switch") --veth-- [attacker netns]
#   [server netns] --veth--/
#
# All three land on the same /24, exactly like the deck's shared L2 segment, so ARP
# spoofing from the attacker namespace works the same way it would on real hardware.
set -euo pipefail

BRIDGE=wscale-br0
NETNS_CLIENT=wscale-client
NETNS_SERVER=wscale-server
NETNS_ATTACKER=wscale-attacker

CLIENT_IP=10.0.0.1/24
SERVER_IP=10.0.0.2/24
ATTACKER_IP=10.0.0.3/24

if [[ $EUID -ne 0 ]]; then
    echo "[!] Run as root (sudo) -- creating namespaces/bridges needs it." >&2
    exit 1
fi

if ip netns list 2>/dev/null | grep -q "$NETNS_CLIENT"; then
    echo "[!] Lab already appears to be up. Run lab/teardown_netns.sh first." >&2
    exit 1
fi

echo "[*] Creating bridge $BRIDGE (the 'Switch')"
ip link add "$BRIDGE" type bridge
ip link set "$BRIDGE" up

create_node() {
    local ns=$1 veth_host=$2 veth_ns=$3 ip=$4
    echo "[*] Creating namespace $ns ($ip)"
    ip netns add "$ns"
    ip link add "$veth_host" type veth peer name "$veth_ns"
    ip link set "$veth_host" master "$BRIDGE"
    ip link set "$veth_host" up
    ip link set "$veth_ns" netns "$ns"
    ip netns exec "$ns" ip link set lo up
    ip netns exec "$ns" ip link set "$veth_ns" name eth0
    ip netns exec "$ns" ip addr add "$ip" dev eth0
    ip netns exec "$ns" ip link set eth0 up
}

create_node "$NETNS_CLIENT"   veth-c-br veth-c "$CLIENT_IP"
create_node "$NETNS_SERVER"   veth-s-br veth-s "$SERVER_IP"
create_node "$NETNS_ATTACKER" veth-a-br veth-a "$ATTACKER_IP"

echo
echo "[*] Topology ready:"
echo "    client   10.0.0.1  ->  ip netns exec $NETNS_CLIENT   <cmd>"
echo "    server   10.0.0.2  ->  ip netns exec $NETNS_SERVER   <cmd>"
echo "    attacker 10.0.0.3  ->  ip netns exec $NETNS_ATTACKER <cmd>"
echo
echo "[*] Attacker is on the segment but NOT yet on-path -- it only gets there once"
echo "    attacker/arp_spoof.py is run (see measure/run_attack.sh)."
echo
echo "[*] Sanity check: client -> server ping"
ip netns exec "$NETNS_CLIENT" ping -c1 -W1 10.0.0.2 && echo "[*] OK" || echo "[!] ping failed, check the setup"
