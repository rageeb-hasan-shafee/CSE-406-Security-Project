#!/usr/bin/env python3
"""Post-hoc detector for the "Observable signatures" called out in Expected Outcome:
  - a WScale mismatch between the SYNs of the same flow (the attacker re-injects a
    tampered frame with a different Ethernet source/dest but the same IP 5-tuple, so
    a single bridge-side capture shows both the original and the edited SYN)
  - anomalously small effective windows on data packets once a scale is applied

Run against a pcap captured on the bridge (wscale-br0), which sees every frame the
attacker re-injects:
    python3 analysis/detect_wscale_mismatch.py captures/attack/handshake.pcap
"""
import argparse
import sys
from collections import defaultdict

try:
    from scapy.all import TCP, rdpcap
except ImportError:
    sys.exit("This script needs scapy: pip install -r requirements.txt")


def wscale_of(tcp):
    for name, value in tcp.options:
        if name == "WScale":
            return value
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap")
    args = ap.parse_args()

    packets = rdpcap(args.pcap)
    syns = defaultdict(list)  # (src,dst,sport,dport,seq) -> [(time,is_ack,wscale)]
    last_wscale = {}  # (src,dst,sport,dport) -> most recently negotiated wscale
    anomalies = []

    for pkt in packets:
        if not pkt.haslayer(TCP) or not pkt.haslayer("IP"):
            continue
        ip = pkt["IP"]
        tcp = pkt[TCP]
        flow = (ip.src, ip.dst, tcp.sport, tcp.dport)
        flag_bits = tcp.flags.value if hasattr(tcp.flags, "value") else int(tcp.flags)
        is_syn = bool(flag_bits & 0x02)
        is_ack = bool(flag_bits & 0x10)

        if is_syn:
            key = flow + (tcp.seq,)
            w = wscale_of(tcp)
            syns[key].append((float(pkt.time), is_ack, w))
            if w is not None:
                last_wscale[flow] = w
        elif flow in last_wscale:
            window = tcp.window * (2 ** last_wscale[flow])
            if window < 16 * 1024:
                anomalies.append((float(pkt.time), flow, tcp.window, last_wscale[flow], window))

    print("=== SYN / SYN-ACK WScale values per flow ===")
    mismatches = 0
    for key, obs in sorted(syns.items(), key=lambda kv: kv[1][0][0]):
        src, dst, sport, dport, seq = key
        values = sorted({w for _, _, w in obs if w is not None})
        tag = "SYN-ACK" if any(a for _, a, _ in obs) else "SYN"
        flag = "  <-- MISMATCH (tampered in flight)" if len(values) > 1 else ""
        print(f"{src}:{sport} -> {dst}:{dport}  seq={seq}  [{tag}]  wscale values seen: {values}{flag}")
        if len(values) > 1:
            mismatches += 1

    print("\n=== Anomalously small effective windows (< 16 KiB) on data packets ===")
    for t, flow, win, wscale, eff in anomalies[:20]:
        print(
            f"t={t:.3f}  {flow[0]}:{flow[2]} -> {flow[1]}:{flow[3]}  "
            f"advertised_window={win}  wscale={wscale}  effective={eff} bytes"
        )
    if len(anomalies) > 20:
        print(f"... and {len(anomalies) - 20} more")

    print(f"\n[*] {mismatches} flow(s) with a WScale mismatch, {len(anomalies)} anomalously small window packet(s).")
    if mismatches or anomalies:
        print("[*] Evidence of a successful window-scale desync attack.")
    else:
        print("[*] No tampering signatures found in this capture.")


if __name__ == "__main__":
    main()
