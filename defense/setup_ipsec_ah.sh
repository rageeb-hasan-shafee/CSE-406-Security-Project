#!/usr/bin/env bash
# Defense: "Integrity at the transport/network layer" (deck, Defense Ideas). Configures
# IPsec AH (Authentication Header) in transport mode between client and server using
# Linux's native ip-xfrm stack and a manually pre-shared key -- no IKE daemon needed for
# a controlled lab demo. AH authenticates the whole IP payload, TCP header included, so
# any in-flight edit to the TCP options (like the WScale rewrite) invalidates the
# Integrity Check Value; the receiving kernel drops the tampered packet before it ever
# reaches the TCP stack. This is exactly the mechanism the deck calls out: "TLS does not
# protect the TCP header, so it won't stop this; IPsec AH/ESP authenticates the segment
# and defeats option tampering."
#
# LAB-ONLY WARNING: the key below is a fixed, hardcoded demo key with no key exchange.
# This is intentionally insecure and is not how IPsec is deployed in production (which
# uses IKE for key negotiation and rotation) -- it exists here purely to demonstrate the
# authentication mechanism itself.
#
# Usage (run in the host namespace, as root, lab must already be up):
#   sudo bash defense/setup_ipsec_ah.sh apply
#   sudo bash defense/setup_ipsec_ah.sh remove
set -euo pipefail
ACTION="${1:?usage: setup_ipsec_ah.sh apply|remove}"

if [[ $EUID -ne 0 ]]; then
    echo "[!] Run as root (sudo)." >&2
    exit 1
fi

CLIENT_IP=10.0.0.1
SERVER_IP=10.0.0.2
SPI_C2S=0x1001
SPI_S2C=0x1002
# 160-bit (20-byte) demo key for hmac-sha1-96. Fixed/hardcoded -- lab only, see warning above.
AH_KEY=0x1234567890abcdef1234567890abcdef12345678

# Both namespaces need BOTH states (c2s and s2c): each side must be able to both
# generate its own outbound AH ICV and verify the peer's inbound one, using the same
# shared key. Policies, however, are direction/namespace-specific -- each side only
# ever sends as itself and receives as itself, so each gets exactly one out + one in
# policy, not all four.
add_states() {
    local ns="$1"
    ip netns exec "$ns" ip xfrm state add src "$CLIENT_IP" dst "$SERVER_IP" proto ah spi "$SPI_C2S" \
        auth-trunc "hmac(sha1)" "$AH_KEY" 96 mode transport
    ip netns exec "$ns" ip xfrm state add src "$SERVER_IP" dst "$CLIENT_IP" proto ah spi "$SPI_S2C" \
        auth-trunc "hmac(sha1)" "$AH_KEY" 96 mode transport
}

apply_client() {
    add_states wscale-client
    ip netns exec wscale-client ip xfrm policy add src "$CLIENT_IP" dst "$SERVER_IP" dir out \
        tmpl src "$CLIENT_IP" dst "$SERVER_IP" proto ah mode transport
    ip netns exec wscale-client ip xfrm policy add src "$SERVER_IP" dst "$CLIENT_IP" dir in \
        tmpl src "$SERVER_IP" dst "$CLIENT_IP" proto ah mode transport
}

apply_server() {
    add_states wscale-server
    ip netns exec wscale-server ip xfrm policy add src "$SERVER_IP" dst "$CLIENT_IP" dir out \
        tmpl src "$SERVER_IP" dst "$CLIENT_IP" proto ah mode transport
    ip netns exec wscale-server ip xfrm policy add src "$CLIENT_IP" dst "$SERVER_IP" dir in \
        tmpl src "$CLIENT_IP" dst "$SERVER_IP" proto ah mode transport
}

remove_side() {
    local ns="$1"
    ip netns exec "$ns" ip xfrm state flush 2>/dev/null || true
    ip netns exec "$ns" ip xfrm policy flush 2>/dev/null || true
}

if [[ "$ACTION" == "apply" ]]; then
    echo "[*] Configuring IPsec AH (transport mode) on client and server namespaces"
    apply_client
    apply_server
    echo "[*] Client SAs:"; ip netns exec wscale-client ip xfrm state show
    echo "[*] Server SAs:"; ip netns exec wscale-server ip xfrm state show
    echo "[*] Client policies:"; ip netns exec wscale-client ip xfrm policy show
    echo "[*] Server policies:"; ip netns exec wscale-server ip xfrm policy show
    echo "[*] IPsec AH applied. All client<->server traffic is now AH-authenticated."

elif [[ "$ACTION" == "remove" ]]; then
    remove_side wscale-client
    remove_side wscale-server
    echo "[*] IPsec AH state/policy flushed on both sides."
else
    echo "unknown action: $ACTION" >&2
    exit 1
fi
