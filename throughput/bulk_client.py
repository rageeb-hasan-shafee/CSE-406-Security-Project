#!/usr/bin/env python3
"""Bulk-transfer client -- the iperf3 substitute counterpart to bulk_server.py.
Connects, pulls --size bytes, measures wall-clock throughput and reads its own
TCP_INFO (the window scale it negotiated, RTT as this endpoint sees it).

Run in the client namespace:
    ip netns exec wscale-client python3 throughput/bulk_client.py --host 10.0.0.2 --stats-out out.json
"""
import argparse
import json
import os
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tcpinfo import get_tcp_info  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--size", type=int, default=20 * 1024 * 1024)
    ap.add_argument("--stats-out", default=None)
    ap.add_argument(
        "--rcvbuf", type=int, default=None,
        help="pin the real receive buffer to this many bytes and disable Linux's "
             "autotuning (which otherwise grows it to several MB and hides the "
             "inflate-attack overrun on a fast/short-lived link)",
    )
    args = ap.parse_args()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if args.rcvbuf:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, args.rcvbuf)
    t0 = time.time()
    s.connect((args.host, args.port))
    received = 0
    while received < args.size:
        chunk = s.recv(min(1024 * 1024, args.size - received))
        if not chunk:
            break
        received += len(chunk)
    elapsed = time.time() - t0

    info = get_tcp_info(s)
    stats = {
        "role": "client",
        "peer": f"{args.host}:{args.port}",
        "bytes_received": received,
        "requested_size": args.size,
        "elapsed_s": round(elapsed, 3),
        "throughput_MBps": round(received / elapsed / 1e6, 3) if elapsed > 0 else 0,
        "retransmits": info.get("retransmits"),
        "total_retrans": info.get("total_retrans"),
        "snd_cwnd": info.get("snd_cwnd"),
        "rtt_us": info.get("rtt"),
        "snd_wscale": info.get("snd_wscale"),
        "rcv_wscale": info.get("rcv_wscale"),
    }
    print("[*] client-side tcp_info:", json.dumps(stats, indent=2))
    s.close()

    if args.stats_out:
        with open(args.stats_out, "w") as f:
            json.dump(stats, f, indent=2)

    if received < args.size:
        print(f"[!] short read: got {received} of {args.size} bytes (connection likely stalled)")


if __name__ == "__main__":
    main()
