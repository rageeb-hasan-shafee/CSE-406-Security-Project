#!/usr/bin/env python3
"""Defense: "Detection (IDS)" (deck, Defense Ideas): "A Zeek/Snort rule flagging a
wscale mismatch between SYN and SYN-ACK, or anomalous window sizes."

Zeek is not available through this system's default package repositories, and
Snort/Suricata's rule language has no built-in way to compare a TCP option's raw value
across two different packets of the same flow (which a wscale-mismatch check inherently
needs) without custom scripting. Rather than ship an untested rule, this reuses the same
detection logic already validated offline in analysis/detect_wscale_mismatch.py, run
live against a capture interface instead of a saved pcap -- functionally the same
"IDS rule" the deck describes, just implemented directly. A reference Zeek script with
equivalent logic is provided in defense/wscale_ids.zeek for documentation purposes.

Run on the bridge (sees both hops of an on-path MITM, so it can compare the two SYNs):
    sudo python3 defense/live_ids.py --iface wscale-br0
"""
import argparse
import sys
import time
from collections import defaultdict

from scapy.all import IP, TCP, sniff


def wscale_of(tcp):
    for name, value in tcp.options:
        if name == "WScale":
            return value
    return None


def make_handler(seen_by_seq, last_wscale, alert_count):
    def handle(pkt):
        if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
            return
        ip = pkt[IP]
        tcp = pkt[TCP]
        flow = (ip.src, ip.dst, tcp.sport, tcp.dport)
        flag_bits = tcp.flags.value if hasattr(tcp.flags, "value") else int(tcp.flags)
        is_syn = bool(flag_bits & 0x02)

        if is_syn:
            key = flow + (tcp.seq,)
            w = wscale_of(tcp)
            prev = seen_by_seq.get(key)
            if w is not None:
                last_wscale[flow] = w
                if prev is not None and prev != w:
                    alert_count[0] += 1
                    print(
                        f"[ALERT] {time.strftime('%H:%M:%S')}  WScale mismatch on "
                        f"{ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport} (seq={tcp.seq}): "
                        f"first saw {prev}, now {w} -- SYN tampered in flight"
                    )
                seen_by_seq[key] = w
        elif flow in last_wscale:
            window = tcp.window * (2 ** last_wscale[flow])
            if window < 16 * 1024:
                alert_count[0] += 1
                print(
                    f"[ALERT] {time.strftime('%H:%M:%S')}  Anomalous window on "
                    f"{ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport}: advertised="
                    f"{tcp.window} wscale={last_wscale[flow]} effective={window} bytes"
                )

    return handle


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--iface", default="wscale-br0")
    ap.add_argument("--count", type=int, default=0, help="stop after N packets (0 = run until Ctrl+C)")
    args = ap.parse_args()

    seen_by_seq = {}
    last_wscale = {}
    alert_count = [0]

    print(f"[*] live_ids.py watching {args.iface} for WScale tampering -- Ctrl+C to stop")
    try:
        sniff(iface=args.iface, prn=make_handler(seen_by_seq, last_wscale, alert_count), count=args.count, store=False)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        sys.exit("[!] needs root (raw socket access) -- run with sudo")

    print(f"\n[*] Stopped. {alert_count[0]} alert(s) raised this run.")


if __name__ == "__main__":
    main()
