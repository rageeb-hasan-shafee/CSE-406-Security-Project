#!/usr/bin/env python3
"""Compare baseline vs attack stats produced by throughput/bulk_client.py +
bulk_server.py. Implements the "measurable impact... quantified against baseline"
line from the Success Criteria slide.
"""
import argparse
import json
import os


def load(path):
    if not path or not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


def row(label, client, server):
    tput = client.get("throughput_MBps") if client else None
    retr = server.get("total_retrans") if server else None
    rtt = server.get("rtt_us") if server else None
    wsc = f"snd={client.get('snd_wscale')}/rcv={client.get('rcv_wscale')}" if client else "?"
    print(
        f"{label:10s} | throughput={str(tput):>10} MB/s | total_retrans={str(retr):>6} "
        f"| rtt={str(rtt):>8} us | client wscale {wsc}"
    )


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--baseline-dir")
    ap.add_argument("--attack-dir")
    ap.add_argument("--show-only", choices=["baseline", "attack", "both"], default="both")
    args = ap.parse_args()

    b_client = load(os.path.join(args.baseline_dir, "client_stats.json")) if args.baseline_dir else None
    b_server = load(os.path.join(args.baseline_dir, "server_stats.json")) if args.baseline_dir else None
    a_client = load(os.path.join(args.attack_dir, "client_stats.json")) if args.attack_dir else None
    a_server = load(os.path.join(args.attack_dir, "server_stats.json")) if args.attack_dir else None

    print("\n=== Throughput / retransmit comparison ===")
    if args.show_only in ("baseline", "both") and b_client:
        row("baseline", b_client, b_server)
    if args.show_only in ("attack", "both") and a_client:
        row("attack", a_client, a_server)

    if b_client and a_client and b_client.get("throughput_MBps"):
        drop = 100 * (1 - a_client["throughput_MBps"] / b_client["throughput_MBps"])
        direction = "DROP" if drop > 0 else "increase"
        print(f"\n[*] Throughput change vs baseline: {drop:+.1f}% ({direction})")
    print()


if __name__ == "__main__":
    main()
