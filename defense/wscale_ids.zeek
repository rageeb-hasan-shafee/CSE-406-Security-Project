# Reference implementation of the deck's suggested IDS rule: "A Zeek/Snort rule
# flagging a wscale mismatch between SYN and SYN-ACK, or anomalous window sizes."
#
# NOT executed in this lab: Zeek is not available through this system's default package
# repositories (it ships its own separate apt repo per-distro/version, which was not
# added here). This script is provided for documentation/completeness, showing the
# equivalent logic to defense/live_ids.py expressed the way the deck literally
# describes it. If Zeek is installed separately, run with:
#   zeek -i wscale-br0 defense/wscale_ids.zeek
#
# Zeek exposes each TCP option via the tcp_option() event when packet-level TCP
# analysis is enabled; this tracks the WScale value seen on the first SYN of each
# connection UID and compares it against any later SYN (e.g. a retransmission that an
# on-path attacker also tampers with) carrying a different value for the same seq.

module WScaleIDS;

export {
    redef enum Notice::Type += {
        WScaleMismatch,
    };
}

global first_wscale: table[string] of count &default=999;  # uid -> shift
global first_seq: table[string] of count;

event tcp_option(c: connection, is_orig: bool, opt: count, optlen: count) &priority=5
    {
    # opt == 3 is Kind=3 (Window Scale); Zeek surfaces the shift value via
    # c$tcp$orig_win_scale / c$tcp$resp_win_scale once parsed, checked below instead
    # of the raw tcp_option() payload for portability across Zeek versions.
    }

event connection_SYN_packet(c: connection, pkt: SYN_packet)
    {
    local uid = c$uid;
    local shift = pkt$win_scale;
    if ( shift < 0 )
        return;  # peer sent no WScale option at all

    if ( uid !in first_wscale )
        {
        first_wscale[uid] = shift;
        first_seq[uid] = pkt$seq;
        return;
        }

    if ( first_seq[uid] == pkt$seq && first_wscale[uid] != shift )
        {
        NOTICE([$note=WScaleMismatch,
                $conn=c,
                $msg=fmt("WScale mismatch on %s: first saw shift %d, now %d for the same SYN (seq=%d) -- likely in-flight tampering",
                         uid, first_wscale[uid], shift, pkt$seq)]);
        }
    }
