#!/bin/sh
# DPI stand (docs/PLAN.md §6): the client is the root namespace, the server and the "DPI" live in namespace $NS.
# The DPI is iptables in the server namespace; each block type gets its own server address:
#   .11 open        nothing
#   .12 sni-rst     RST when the ClientHello carries "sni.test"           (SNI_BLOCK, reset)
#   .13 sni-drop    drop when the ClientHello carries "drop.test"         (SNI_BLOCK, silence)
#   .14 ip-drop     everything to the address is dropped                  (IP_BLOCK)
#   .15 port-drop   TCP 443 dropped, 80 open                              (PORT_BLOCK)
#   .16 cutoff      server data stops after 20000 bytes per connection    (CUTOFF_16K)
#   .17 kyber       TLS records in packets of 1400+ bytes are dropped     (KYBER_MULTIPKT)
#   .18 fingerprint hellos with Chrome's new ALPS extension are reset     (FINGERPRINT)
#   .19 redirect    plain HTTP for redirect.test answers 302 elsewhere    (HTTP_BLOCK, by the server)
#   .20 volume      the flow dies after 16000 bytes in both directions     (CUTOFF_16K on a small page, padded probe)
# Usage: stand.sh up CERT KEY | down. Needs root, iproute2, iptables (string, connbytes, u32, length) and python3.
set -eu
NS=${ZT_STAND_NS:-ztstand}
NET=${ZT_STAND_NET:-10.124.0}
DIR=$(cd "$(dirname "$0")" && pwd)

down() {
    ip netns pids "$NS" 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip link del zts0 2>/dev/null || true
    ip netns del "$NS" 2>/dev/null || true
}

up() {
    down
    ip netns add "$NS"
    ip link add zts0 type veth peer name zts1
    ip link set zts1 netns "$NS"
    ip addr add "$NET.1/24" dev zts0
    ip link set zts0 up
    x() { ip netns exec "$NS" "$@"; }
    x ip link set lo up
    x ip link set zts1 up
    x ip addr add "$NET.2/24" dev zts1
    for i in 11 12 13 14 15 16 17 18 19 20; do x ip addr add "$NET.$i/32" dev zts1; done
    x sysctl -qw net.netfilter.nf_conntrack_acct=1 2>/dev/null || true

    T="-p tcp --dport 443"
    x iptables -A INPUT -d "$NET.12" $T -m string --string sni.test --algo bm -j REJECT --reject-with tcp-reset
    x iptables -A INPUT -d "$NET.13" $T -m string --string drop.test --algo bm -j DROP
    x iptables -A INPUT -d "$NET.14" -j DROP
    x iptables -A INPUT -d "$NET.15" $T -j DROP
    x iptables -A OUTPUT -s "$NET.16" -p tcp --sport 443 -m connbytes --connbytes 20000: --connbytes-dir reply --connbytes-mode bytes -j DROP
    x iptables -A INPUT -d "$NET.20" $T -m connbytes --connbytes 16000: --connbytes-dir both --connbytes-mode bytes -j DROP
    x iptables -A OUTPUT -s "$NET.20" -p tcp --sport 443 -m connbytes --connbytes 16000: --connbytes-dir both --connbytes-mode bytes -j DROP
    # first byte of the TCP payload is 0x16 (TLS handshake) and the packet is 1400 bytes or more
    x iptables -A INPUT -d "$NET.17" $T -m length --length 1400: -m u32 --u32 "0>>22&0x3C@12>>26&0x3C@0>>24=0x16" -j DROP
    # application_settings 0x44cd with a 5-byte body: only Chrome 120+ sends it
    x iptables -A INPUT -d "$NET.18" $T -m string --hex-string "|44cd0005|" --algo bm -j REJECT --reject-with tcp-reset

    ip netns exec "$NS" python3 "$DIR/server.py" "$1" "$2" >/dev/null 2>&1 &
    for _ in $(seq 50); do
        if ip netns exec "$NS" sh -c "ss -ltn | grep -q ':443 '"; then exit 0; fi
        sleep 0.1
    done
    echo "server did not start" >&2
    exit 1
}

case "${1:-}" in
    up) up "$2" "$3" ;;
    down) down ;;
    *) echo "usage: $0 up CERT KEY | down" >&2; exit 2 ;;
esac
