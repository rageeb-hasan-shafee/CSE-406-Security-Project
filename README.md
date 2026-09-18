# TCP Window Scaling Attack — Implementation

Implements the attack described in `Security_Project.pdf` up through **Expected
Outcome**: an on-path (ARP-spoofing) MITM rewrites the TCP Window Scale option during
the handshake so client and server desync on the window multiplier, plus the
Slow-Read/zero-window fallback DoS. **Defense Ideas (deck section 6) are intentionally
not implemented yet** — that's the next phase.

Only ever run this against hosts you control. The lab below is self-contained (Linux
network namespaces on one machine standing in for the deck's "3 VMs / Linux network
namespaces" option) — nothing here touches real network hardware.

## 1. Prerequisites

```bash
sudo apt-get install -y iproute2 iptables tcpdump python3-pip python3-venv \
    build-essential python3-dev libnetfilter-queue-dev

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

`NetfilterQueue` needs `libnetfilter-queue-dev` to build; `scapy` is pure Python.
Everything below that touches namespaces, iptables, or raw sockets needs root — run it
with `sudo` (or `sudo -E` after activating the venv, or use `sudo .venv/bin/python3 ...`).

## 2. Topology (deck: "Network Topology & Components")

```
[client netns 10.0.0.1] --veth--\
                                  wscale-br0 (bridge = "Switch") --veth-- [attacker netns 10.0.0.3]
[server netns 10.0.0.2] --veth--/
```

```bash
sudo bash lab/setup_netns.sh      # build the topology, sanity-pings client -> server
...                                # run the steps below
sudo bash lab/teardown_netns.sh   # tear it all down when done
```

## 3. Capture a baseline (Implementation Plan step 1)

```bash
sudo bash measure/run_baseline.sh
```

Captures `captures/baseline/handshake.pcap`, and each side's throughput/TCP_INFO
(retransmits, RTT, window scale) as `client_stats.json` / `server_stats.json` — the
iperf3 substitute described on the "Implementation: Core Rewrite" slide's neighbor
step, done in plain Python since iperf3 isn't required here.

## 4. Run the attack (Implementation Plan steps 2-5)

```bash
# deflate: server ends up thinking the client's window is unscaled (shift 7 -> 0)
sudo bash measure/run_attack.sh 0 client-syn

# inflate: sender overshoots the real window (shift 0 -> 14), try this variant too
sudo bash measure/run_attack.sh 14 client-syn
```

This chains:
1. **Gain MITM** — `attacker/arp_spoof.py` poisons both client and server.
2. **Divert** — `attacker/divert_rules.sh setup` installs the NFQUEUE rule from the
   deck's "Implementation Plan" slide (`iptables -t mangle -A FORWARD -p tcp
   --tcp-flags SYN SYN -j NFQUEUE --queue-num 0`, plus `--queue-bypass` so the path
   fails open if the handler isn't running).
3. **Rewrite** — `attacker/wscale_attack.py` is the NFQUEUE callback: finds the
   `WScale` TCP option, overwrites the shift byte, deletes both checksums so scapy
   recomputes them, reinjects. Only edits the client's plain SYN by default
   (`--target client-syn`), matching the "Timing Diagram: Handshake Tampering" slide;
   pass `--target server-synack` or `--target both` to tamper the other direction.
4. **Measure** — same bulk-transfer client/server as the baseline, run again with the
   MITM active.
5. Prints a throughput/retransmit comparison against the baseline
   (`measure/compare.py`) and runs the pcap-based mismatch detector
   (`analysis/detect_wscale_mismatch.py`) over the captured handshake.

Rewrites are also logged live to `captures/attack/wscale_attack.log`.

## 5. Slow-Read / zero-window fallback (deck: "guaranteed-working backup")

```bash
sudo ip netns exec wscale-server python3 server/http_server.py --port 8000 --max-conns 20 &
sudo ip netns exec wscale-client python3 slowread/slow_read_client.py --host 10.0.0.2 --port 8000
```

`slow_read_client.py` opens 50 connections with an 8-byte `SO_RCVBUF` and reads a
handful of bytes per second, so the server's `send()` blocks on the near-zero window
and each connection pins one of the server's 20 worker slots. It health-checks the
server before, during, and after the attack — watch the "DENIED / degraded" line
during the run.

## 6. Expected Outcome — what "success" looks like

Matches the deck's Expected Outcome / Success Criteria slides:

- **Deflated scale (7→0):** client throughput collapses toward the ~64 KB
  unscaled-window regime — compare `client_stats.json` throughput before/after.
- **Inflated scale (0→14):** sender oversends past the real window — watch
  `total_retrans` and `rtt_us` spike in `server_stats.json`, possibly a stalled/short
  transfer on the client side.
- **Slow-read variant:** `/health` requests get denied or stall once the 20-connection
  pool is exhausted — low-bandwidth DoS, no window-scale tampering needed.
- **Observable signatures**, all surfaced by `analysis/detect_wscale_mismatch.py`:
  a WScale mismatch between the two SYNs of the same flow (the bridge capture sees
  both the original and the attacker's re-injected frame), anomalously small effective
  windows (`advertised_window * 2^wscale`) on data packets, and the throughput/RTT
  delta reported by `measure/compare.py`.

## Layout

```
lab/        netns/bridge topology setup + teardown
attacker/   arp_spoof.py, divert_rules.sh, wscale_attack.py (the core rewrite)
server/     bounded-pool HTTP server (throughput + slow-read target)
throughput/ bulk_server.py / bulk_client.py / tcpinfo.py (iperf3 substitute)
slowread/   slow_read_client.py (fallback DoS)
measure/    run_baseline.sh, run_attack.sh, compare.py
analysis/   detect_wscale_mismatch.py (pcap -> mismatch/anomaly report)
captures/   pcaps + stats JSON land here
```

## Not yet implemented

Deck section 6, **Defense Ideas** (IPsec/AH-ESP, Zeek/Snort detection rule, Dynamic
ARP Inspection / DHCP snooping / 802.1X, slow-read hardening, middlebox hygiene) —
planned as the next phase.
