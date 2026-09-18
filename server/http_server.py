#!/usr/bin/env python3
"""Minimal HTTP server with a bounded connection pool. Doubles as:
  1) the target for the Slow Read / zero-window fallback demo (small pool so
     exhaustion by held-open connections is directly observable), and
  2) a /health endpoint used to prove the DoS: legitimate requests get denied or
     stall once the pool is exhausted.

Run in the server namespace:
    ip netns exec wscale-server python3 server/http_server.py --port 8000 --max-conns 20
"""
import argparse
import socket
import threading

BIGFILE_SIZE_DEFAULT = 20 * 1024 * 1024
CHUNK = 1024 * 1024
PAYLOAD_CHUNK = b"S" * CHUNK


def build_headers(size):
    return (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/octet-stream\r\n"
        f"Content-Length: {size}\r\n"
        "Connection: close\r\n\r\n"
    ).encode()


def handle_client(conn, addr, size):
    conn.settimeout(60)
    request = b""
    while b"\r\n\r\n" not in request and len(request) < 8192:
        chunk = conn.recv(4096)
        if not chunk:
            return
        request += chunk
    first_line = request.split(b"\r\n", 1)[0].decode(errors="replace")

    if first_line.startswith("GET /health"):
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        return

    conn.sendall(build_headers(size))
    sent = 0
    while sent < size:
        n = min(CHUNK, size - sent)
        conn.sendall(PAYLOAD_CHUNK[:n])
        sent += n


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument(
        "--max-conns", type=int, default=20,
        help="bounded worker pool; slow-read holds workers until this is exhausted",
    )
    ap.add_argument("--size", type=int, default=BIGFILE_SIZE_DEFAULT, help="bytes served at GET /bigfile")
    args = ap.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.host, args.port))
    sock.listen(128)
    print(f"[*] listening on {args.host}:{args.port}  max_conns={args.max_conns}  size={args.size}")

    sem = threading.Semaphore(args.max_conns)

    def worker(conn, addr):
        if not sem.acquire(timeout=0.001):
            print(f"[!] pool exhausted ({args.max_conns} active) -- rejecting {addr}")
            try:
                conn.close()
            except OSError:
                pass
            return
        try:
            print(f"[+] conn from {addr}")
            handle_client(conn, addr, args.size)
        except (socket.timeout, ConnectionError, OSError) as e:
            print(f"[-] conn {addr} error/timeout: {e}")
        finally:
            conn.close()
            sem.release()

    while True:
        conn, addr = sock.accept()
        threading.Thread(target=worker, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
