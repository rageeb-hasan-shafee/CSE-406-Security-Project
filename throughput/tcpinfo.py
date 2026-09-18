"""Parse Linux TCP_INFO so the measurement scripts can observe window scale,
retransmits, RTT and cwnd directly from the kernel -- no iperf3 required.

Used for the "Observable signatures" in the Expected Outcome slide: wscale mismatch,
anomalous window sizes, throughput drop / RTT spike vs baseline.
"""
import socket
import struct

# Stable prefix of struct tcp_info (linux/tcp.h). Kernels keep appending fields at the
# end, so we only decode this well-known prefix and ignore anything past it.
_FIELDS = [
    ("state", "B"), ("ca_state", "B"), ("retransmits", "B"), ("probes", "B"),
    ("backoff", "B"), ("options", "B"), ("wscale", "B"), ("delivery_rate_app_limited", "B"),
    ("rto", "I"), ("ato", "I"), ("snd_mss", "I"), ("rcv_mss", "I"),
    ("unacked", "I"), ("sacked", "I"), ("lost", "I"), ("retrans", "I"),
    ("fackets", "I"), ("last_data_sent", "I"), ("last_ack_sent", "I"),
    ("last_data_recv", "I"), ("last_ack_recv", "I"), ("pmtu", "I"),
    ("rcv_ssthresh", "I"), ("rtt", "I"), ("rttvar", "I"), ("snd_ssthresh", "I"),
    ("snd_cwnd", "I"), ("advmss", "I"), ("reordering", "I"), ("rcv_rtt", "I"),
    ("rcv_space", "I"), ("total_retrans", "I"),
]
_FMT = "=" + "".join(f for _, f in _FIELDS)
_SIZE = struct.calcsize(_FMT)


def get_tcp_info(sock: socket.socket) -> dict:
    """Return a dict of the fields above, plus split-out snd_wscale/rcv_wscale."""
    raw = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 256)
    raw = raw[:_SIZE].ljust(_SIZE, b"\x00")
    values = struct.unpack(_FMT, raw)
    info = dict(zip((name for name, _ in _FIELDS), values))
    info["snd_wscale"] = info["wscale"] & 0x0F
    info["rcv_wscale"] = (info["wscale"] >> 4) & 0x0F
    return info
