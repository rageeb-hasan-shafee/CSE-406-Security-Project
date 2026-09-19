# TCP Window Scaling Attack

This project builds and actually runs a network attack, end to end, against a
lab you control — then builds and runs defenses against that same attack, in
the same lab. It's based on `Security_Project.pdf`, a design report describing
a way to abuse a small, easy-to-overlook detail of how TCP negotiates how much
data can be "in flight" at once.

Everything here was executed for real (not just written and assumed to work):
the attack, the measurements, and the defenses were all run against a live lab
on the project author's machine, and the results are written up in
[`report/observation_report.tex`](report/observation_report.tex) with real
numbers, real logs, and an honest account of where the first attempt at each
thing didn't go as predicted and why.

**Only ever run this against hosts you control.** The lab is self-contained —
three Linux network namespaces wired together by a software bridge on one
machine, standing in for three separate computers on a switch. Nothing here
touches real network hardware or anyone else's traffic.

---

## The idea, in plain English

When two computers open a TCP connection, they don't just agree to send data —
they also agree on a *window size*: how many bytes the sender is allowed to
have "in flight" (sent but not yet confirmed received) before it has to pause
and wait. The window size field in a TCP packet is only 16 bits, which caps it
at 65,535 bytes — far too small for modern, fast connections. So there's an
extra, optional trick called **window scaling**: during the initial handshake
(and *only* during the handshake), both sides can agree on a multiplier — a
"shift" value from 0 to 14 — and from then on, every window size either side
advertises is silently multiplied by 2^shift. A shift of 10, for example,
turns a 16-bit field that maxes out at 64 KB into an effective window of up to
64 MB.

Here's the detail this whole project exploits: **that shift value is agreed
once, in the handshake, and never checked again for the rest of the
connection.** Neither side re-announces it, re-verifies it, or has any way to
notice if the other side's understanding of it is wrong.

So: if an attacker can sit *between* the two computers and quietly change that
one number while it's still in transit during the handshake — without
breaking anything else about the packet — the two ends of the connection end
up with two different beliefs about the same number, forever, and neither one
ever finds out. That's the whole attack. Two ways to abuse the resulting
mismatch are demonstrated here:

- **Deflate the shift** (attacker changes it to a *smaller* number): the
  receiver's side thinks the window is far bigger than it's telling the
  sender it actually is now understood to be — so the sender throttles itself
  down to what it wrongly believes is a tiny window, and throughput collapses,
  even though nothing is actually being lost.
- **Inflate the shift** (attacker changes it to a *bigger* number): the sender
  is fooled into believing the receiver can absorb far more data than it
  really can, so it sends past the receiver's real buffer capacity — data
  gets silently dropped, and the connection has to retransmit, over and over.

A third, simpler attack is included as a fallback that doesn't touch any
packets at all: **Slow Read**. A client opens many connections to a server,
tells it (truthfully, this time) that its receive window is tiny, and then
only reads a few bytes every second. The server has to hold each of those
connections open, tying up its limited pool of workers, until it can't accept
any new, legitimate connections. Same *family* of problem (window-size abuse),
completely different mechanism — no packet tampering, no need to be
on-path at all in the MITM sense.

## Terms used throughout this project

| Term | What it means here |
|---|---|
| **TCP handshake** | The SYN → SYN-ACK → ACK exchange that starts every TCP connection. The window-scale shift is only ever announced in the first two of those three packets. |
| **Window Scale option** | An optional field (`Kind=3`) inside the TCP handshake packets carrying the shift value (0–14). Defined in RFC 7323. |
| **MITM (on-path attacker)** | Someone who can see and modify traffic between two other computers as it passes by, without either of them realizing it. |
| **ARP spoofing** | The technique used here to *become* the MITM: lying to a computer's address-resolution cache so it sends traffic meant for its real neighbor to the attacker's machine instead. Works only on the same local network segment. |
| **NFQUEUE** | A Linux kernel feature that lets a normal program (not just kernel code) intercept, inspect, modify, and re-release individual packets in flight. This is how the attacker's rewrite script gets its hands on each packet. |
| **Checksum** | A small integrity value in every IP/TCP packet, recalculated whenever the packet's contents change, so routers can detect basic corruption. Editing a packet means recomputing this — but it is *not* a security mechanism; anyone can recompute it, including an attacker. |
| **`TCP_INFO`** | A Linux socket option that lets a program ask the kernel directly: what window scale did we negotiate, how many retransmits has this connection had, what's the current RTT, etc. Used throughout this project instead of an external tool like `iperf3`, so every number reported is coming straight from the kernel's own bookkeeping. |
| **Slow Read / zero-window DoS** | A denial-of-service technique where a client legitimately advertises a tiny receive window and reads data as slowly as it can, forcing the server to keep the connection (and its resources) tied up for a long time. |
| **IPsec AH (Authentication Header)** | A way to cryptographically sign an entire IP packet (headers included) so that any tampering — even a single byte changed anywhere in it — is detectable by the receiver. Used here as a defense, since it makes the window-scale rewrite detectable/unusable. |
| **IDS (Intrusion Detection System)** | Software that watches traffic and raises an alert when it sees something suspicious, without necessarily blocking anything itself. |

## What's in this repository

```
lab/        Builds/tears down the 3-node lab (client, server, attacker) using
            Linux network namespaces + a bridge acting as the shared switch.
attacker/   The attack itself: ARP spoofing, the NFQUEUE diversion rule, and
            the script that actually rewrites the window-scale byte.
server/     A small HTTP server with a limited connection pool — the target
            for both the throughput tests and the Slow Read fallback.
throughput/ A minimal stand-in for iperf3: a bulk-transfer client/server pair
            that reports real kernel TCP_INFO stats (throughput, retransmits,
            RTT, negotiated window scale) for every run.
slowread/   The Slow Read fallback attack client.
measure/    Orchestration scripts: capture a clean baseline, then run the
            attack and automatically compare the two.
analysis/   Reads a packet capture after the fact and reports any window-scale
            mismatch or suspiciously small effective window it finds.
defense/    The three defenses: blocking the MITM position (static ARP
            entries), cryptographic integrity (IPsec AH), and detection (a
            live version of the analysis script, watching traffic as it
            happens). Also includes a reference Zeek script
            (`wscale_ids.zeek`) showing the same detection idea the way a
            real IDS engine would express it — not run in this lab, since
            Zeek wasn't available to install, but included for reference.
captures/   Where packet captures and measurement results land when you run
            things.
report/     The full write-up (LaTeX), with real results from every attack
            and every defense, including places where the first attempt
            didn't match the prediction and why.
```

## 1. Install what you need

```bash
sudo apt-get install -y iproute2 iptables tcpdump python3-pip python3-venv \
    build-essential python3-dev libnetfilter-queue-dev

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

This installs `scapy` (for building/editing packets) and `NetfilterQueue`
(the Python binding for the NFQUEUE kernel feature explained above).
Everything from here on that touches network namespaces, `iptables`, or raw
sockets needs to run as root — use `sudo`, or `sudo .venv/bin/python3 ...` if
you want it to see the venv's packages.

## 2. Build the lab

```
[client netns 10.0.0.1] --veth--\
                                  wscale-br0 (bridge = "the switch") --veth-- [attacker netns 10.0.0.3]
[server netns 10.0.0.2] --veth--/
```

```bash
sudo bash lab/setup_netns.sh      # creates the three "machines" and pings client -> server
...                                 # (do the steps below)
sudo bash lab/teardown_netns.sh   # cleans everything up when you're done
```

## 3. Record a clean baseline

Before attacking anything, capture what a completely normal transfer looks
like, so later results have something honest to compare against:

```bash
sudo bash measure/run_baseline.sh
```

This starts the small throughput server and client (Section "Terms" above —
the `TCP_INFO`-based iperf3 stand-in) with no attacker involved, and saves a
packet capture plus each side's measured throughput/retransmits/window scale
under `captures/baseline/`.

## 4. Run the attack

```bash
# "deflate": the server ends up believing the client's window is far smaller than it is
sudo bash measure/run_attack.sh 0 client-syn

# "inflate": the server ends up believing the client's window is far bigger than it is
sudo bash measure/run_attack.sh 14 client-syn 65536
#                                        ^^^^^ pins the client's real receive buffer to
#                                              64 KB first -- see the note below on why.
```

Behind the scenes, each run does exactly what the "idea" section above
described, as five concrete steps:

1. **Become the MITM** — `attacker/arp_spoof.py` lies to the client and the
   server about each other's addresses, so their traffic starts flowing
   through the attacker instead of directly to each other.
2. **Intercept the handshake** — `attacker/divert_rules.sh` installs an
   `iptables`/NFQUEUE rule that hands every SYN and SYN-ACK packet to a
   Python program before it's allowed to continue on its way.
3. **Rewrite it** — `attacker/wscale_attack.py` is that program: it finds the
   Window Scale option inside the packet, overwrites just that one byte,
   recomputes the checksums, and lets the packet through. Nothing else about
   the packet changes.
4. **Measure the damage** — the same throughput test from step 3 runs again,
   this time with the tampering active, and its results are compared
   directly against the untampered baseline.
5. **Look for the evidence** — the packet capture from this run is checked
   for the tell-tale sign of tampering: the same connection's SYN showing up
   twice with two different window-scale values (`analysis/detect_wscale_mismatch.py`).

*Why pin the buffer for the "inflate" case?* On a fast, low-latency lab link,
Linux automatically grows a connection's real receive buffer to several
megabytes almost instantly — so a false, inflated window belief never
actually gets tested against a buffer small enough for it to matter, and the
attack looks like it did nothing. Pinning the client's real buffer to a small,
fixed size (`65536` bytes here) gives the false belief something real and
small to actually overrun, which is what reveals the intended effect
(retransmissions, stalls). This is explained in detail, with real before/after
numbers, in the report.

Every rewrite is logged live to `captures/attack/wscale_attack.log`, and each
run saves its own timestamped copy of the capture and stats so a later run
doesn't overwrite the evidence from an earlier one.

## 5. Run the Slow Read fallback

Two terminals:

```bash
# terminal 1 -- the target server, with a deliberately small connection pool
sudo ip netns exec wscale-server python3 server/http_server.py --port 8000 --max-conns 20

# terminal 2 -- the attack
sudo ip netns exec wscale-client python3 slowread/slow_read_client.py --host 10.0.0.2 --port 8000
```

The client opens 50 connections, each advertising an 8-byte receive window,
and reads only a few bytes every second — so the server ends up with 20
connections (its entire pool) tied up and can't accept anything else. Watch
for the health check in the middle of the run reporting the server as denied
or badly degraded, and recovering right after the attack connections close.

## 6. Run the defenses

Each of these re-runs the *same* attack pipeline from step 4, but with one
defense active first, so you can see directly whether it actually stops
anything:

```bash
sudo bash defense/run_defense_demo.sh arp     # block the MITM position itself
sudo bash defense/run_defense_demo.sh ipsec   # make tampering cryptographically detectable
sudo bash defense/run_defense_demo.sh ids     # detect the tampering as it happens, live
```

- **`arp`** installs a permanent, kernel-enforced entry in each computer's
  address-resolution table for the other one's *real* address, so the
  attacker's ARP lies get ignored outright and it never becomes the MITM in
  the first place.
- **`ipsec`** sets up IPsec AH (see the terms table) between client and
  server with a fixed shared key, so any packet tampering becomes detectable
  in transit.
- **`ids`** runs `defense/live_ids.py`, a live version of the same detector
  used in step 4, watching traffic as it happens and printing an alert the
  moment it sees a mismatched window-scale value or a suspiciously tiny
  effective window.

All three were run for real against the live attack — what actually happened
each time (including a place where the real result differed from what was
predicted going in) is in the report.

## What "it worked" looks like

- **Deflate:** the client's measured throughput collapses hard, with the
  server's `TCP_INFO` showing the wrong (rewritten) window scale it's
  operating on.
- **Inflate (buffer pinned):** the server's `total_retrans` count climbs —
  real, repeated retransmissions from oversending past the client's actual
  buffer.
- **Slow Read:** the server's pool fills up exactly to its configured limit,
  and a legitimate health-check request gets denied or badly delayed until
  the attack connections release.
- **Evidence, either way:** `analysis/detect_wscale_mismatch.py` (or its live
  counterpart, `defense/live_ids.py`) finds the same connection's handshake
  carrying two different window-scale values, and/or data packets whose real
  (scaled) window works out to a suspiciously small number of bytes.

## Where to read the full results

[`report/observation_report.tex`](report/observation_report.tex) has the
complete write-up, with diagrams of the lab, the traffic path, and each
attack's mechanics, and for every attack and every defense: the idea behind
it, the process actually followed, what was expected beforehand, what was
actually observed, an explanation anywhere the two didn't match, the
assumptions everything rests on, and references. Compile it with:

```bash
cd report && pdflatex observation_report.tex && pdflatex observation_report.tex
```
