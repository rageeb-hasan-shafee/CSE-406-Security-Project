#!/usr/bin/env python3
"""Bulk-transfer server -- the iperf3 substitute used by Implementation Plan step 5
("Measure"). Streams --size bytes to each connecting client as fast as the kernel will
let it, then records TCP_INFO (retransmits, cwnd, rtt, wscale) for that connection.

Run in the server namespace:
    ip netns exec wscale-server python3 throughput/bulk_server.py --once --stats-out out.json
"""
import argparse
import json
import os
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tcpinfo import get_tcp_info  # noqa: E402

CHUNK = 1024 * 1024
BUF = b"B" * CHUNK


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--size", type=int, default=20 * 1024 * 1024, help="bytes to send per connection")
    ap.add_argument("--stats-out", default=None, help="write TCP_INFO summary as JSON here")
    ap.add_argument("--once", action="store_true", help="handle a single connection then exit")
    args = ap.parse_args()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(5)
    print(f"[*] bulk_server listening on {args.host}:{args.port}  size={args.size}")

    while True:
        conn, addr = srv.accept()
        print(f"[+] connection from {addr}")
        t0 = time.time()
        sent = 0
        try:
            while sent < args.size:
                n = min(CHUNK, args.size - sent)
                conn.sendall(BUF[:n])
                sent += n
        except (BrokenPipeError, ConnectionResetError, OSError) as e:
            print(f"[!] transfer interrupted after {sent} bytes: {e}")
        elapsed = time.time() - t0

        try:
            info = get_tcp_info(conn)
        except OSError:
            info = {}

        stats = {
            "role": "server",
            "peer": f"{addr[0]}:{addr[1]}",
            "bytes_sent": sent,
            "requested_size": args.size,
            "elapsed_s": round(elapsed, 3),
            "throughput_MBps": round(sent / elapsed / 1e6, 3) if elapsed > 0 else 0,
            "retransmits": info.get("retransmits"),
            "total_retrans": info.get("total_retrans"),
            "snd_cwnd": info.get("snd_cwnd"),
            "rtt_us": info.get("rtt"),
            "snd_wscale": info.get("snd_wscale"),
            "rcv_wscale": info.get("rcv_wscale"),
        }
        print("[*] server-side tcp_info:", json.dumps(stats))
        if args.stats_out:
            with open(args.stats_out, "w") as f:
                json.dump(stats, f, indent=2)

        conn.close()
        if args.once:
            break


if __name__ == "__main__":
    main()
