#!/usr/bin/env python3
"""Builds the packet corpus in tests/pcaps and the tshark reference (expected.json).

Synthesized captures are deterministic (fixed random bytes). Live captures (curl <-> openssl s_server over
loopback) need root, tcpdump, curl and openssl and are only re-made with --live. The reference is always taken
from tshark, so the C# parsers are compared to Wireshark, not to themselves (PLAN 1.4).

    python3 tools/pcaps/make_corpus.py [--live]
"""
import argparse
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives import hashes, hmac

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT = os.path.join(ROOT, "tests", "pcaps")
CLIENT = bytes([10, 0, 0, 2])
SERVER = bytes([203, 0, 113, 10])


def det_bytes(seed, n):
    out = b""
    i = 0
    while len(out) < n:
        out += hashlib.sha256(f"{seed}:{i}".encode()).digest()
        i += 1
    return out[:n]


def csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data)//2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def ipv4(src, dst, proto, payload, ttl=64, ipid=0, df=True):
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, ipid, 0x4000 if df else 0, ttl, proto, 0, src, dst)
    hdr = hdr[:10] + struct.pack("!H", csum(hdr)) + hdr[12:]
    return hdr + payload


def tcp(src, dst, sport, dport, seq, ack, flags, payload=b"", ttl=64, ipid=0, opts=b""):
    off = (20 + len(opts)) // 4
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, off << 4, flags, 64240, 0, 0) + opts
    pseudo = src + dst + struct.pack("!BBH", 0, 6, len(hdr) + len(payload))
    c = csum(pseudo + hdr + payload)
    hdr = hdr[:16] + struct.pack("!H", c) + hdr[18:]
    return ipv4(src, dst, 6, hdr + payload, ttl, ipid)


def udp(src, dst, sport, dport, payload, ttl=64):
    hdr = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    pseudo = src + dst + struct.pack("!BBH", 0, 17, 8 + len(payload))
    c = csum(pseudo + hdr + payload) or 0xFFFF
    hdr = hdr[:6] + struct.pack("!H", c)
    return ipv4(src, dst, 17, hdr + payload, ttl)


def write_pcap(path, packets):
    """Classic pcap, LINKTYPE_RAW (101). packets: list of (time, bytes)."""
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
        for t, p in packets:
            sec = int(t)
            us = int(round((t - sec) * 1e6))
            f.write(struct.pack("<IIII", sec, us, len(p), len(p)))
            f.write(p)


# --- TLS ClientHello builder ---

def ext(t, body):
    return struct.pack("!HH", t, len(body)) + body


def client_hello(sni, alpn, groups, key_shares, ciphers, sigalgs, extra=(), grease=True, ech=None, seed="ch"):
    exts = []
    if grease:
        exts.append(ext(0x3A3A, b""))
    if sni is not None:
        name = sni.encode()
        exts.append(ext(0x0000, struct.pack("!HBH", len(name) + 3, 0, len(name)) + name))
    exts.append(ext(0x0017, b""))  # extended_master_secret
    exts.append(ext(0xFF01, b"\0"))  # renegotiation_info
    g = struct.pack(f"!{len(groups)}H", *groups)
    exts.append(ext(0x000A, struct.pack("!H", len(g)) + g))
    exts.append(ext(0x000B, b"\x01\x00"))  # ec_point_formats
    exts.append(ext(0x0023, b""))  # session_ticket
    if alpn:
        a = b"".join(bytes([len(x)]) + x.encode() for x in alpn)
        exts.append(ext(0x0010, struct.pack("!H", len(a)) + a))
    exts.append(ext(0x0005, b"\x01\x00\x00\x00\x00"))  # status_request
    s = struct.pack(f"!{len(sigalgs)}H", *sigalgs)
    exts.append(ext(0x000D, struct.pack("!H", len(s)) + s))
    ks = b""
    for grp, n in key_shares:
        ks += struct.pack("!HH", grp, n) + det_bytes(f"{seed}:ks:{grp}", n)
    exts.append(ext(0x0033, struct.pack("!H", len(ks)) + ks))
    exts.append(ext(0x002D, b"\x01\x01"))  # psk_key_exchange_modes
    vers = [0x0304, 0x0303]
    if grease:
        vers = [0x4A4A] + vers
    v = struct.pack(f"!{len(vers)}H", *vers)
    exts.append(ext(0x002B, bytes([len(v)]) + v))
    for t, body in extra:
        exts.append(ext(t, body))
    if ech is not None:
        exts.append(ext(0xFE0D, ech))
    if grease:
        exts.append(ext(0x1A1A, b"\0"))
    e = b"".join(exts)
    cs = ([0x2A2A] if grease else []) + ciphers
    body = (struct.pack("!H", 0x0303) + det_bytes(seed + ":random", 32) + b"\x20" + det_bytes(seed + ":sid", 32)
            + struct.pack("!H", 2 * len(cs)) + struct.pack(f"!{len(cs)}H", *cs) + b"\x01\x00"
            + struct.pack("!H", len(e)) + e)
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return hs


def record(hs):
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


CHROME_CIPHERS = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035]
CHROME_SIGALGS = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]


def tcp_session(name, payload, mss=1400, rst=None, t0=1700000000.0):
    """SYN, SYN-ACK, ACK, client payload in segments of mss, optional RST (ttl, ipid, delay)."""
    cport, sport = 51515, 443
    cisn, sisn = 1000, 50000
    pk = []
    t = t0
    pk.append((t, tcp(CLIENT, SERVER, cport, sport, cisn, 0, 0x02, ttl=64, ipid=100)))
    t += 0.030
    pk.append((t, tcp(SERVER, CLIENT, sport, cport, sisn, cisn + 1, 0x12, ttl=52, ipid=0)))
    t += 0.0001
    pk.append((t, tcp(CLIENT, SERVER, cport, sport, cisn + 1, sisn + 1, 0x10, ttl=64, ipid=101)))
    seq = cisn + 1
    for i in range(0, len(payload), mss):
        seg = payload[i:i + mss]
        t += 0.0001
        pk.append((t, tcp(CLIENT, SERVER, cport, sport, seq, sisn + 1, 0x18, seg, ttl=64, ipid=102 + i // mss)))
        seq += len(seg)
    if rst is not None:
        ttl, ipid, delay = rst
        t += delay
        pk.append((t, tcp(SERVER, CLIENT, sport, cport, sisn + 1, seq, 0x14, ttl=ttl, ipid=ipid)))
    write_pcap(os.path.join(OUT, name), pk)


# --- QUIC (RFC 9001 Appendix A) ---

def hkdf_expand_label(secret, label, length):
    full = b"tls13 " + label.encode()
    info = struct.pack("!HB", length, len(full)) + full + b"\0"
    return HKDFExpand(hashes.SHA256(), length, info).derive(secret)


def hkdf_extract(salt, ikm):
    h = hmac.HMAC(salt, hashes.SHA256())
    h.update(ikm)
    return h.finalize()


def quic_client_initial(dcid, scid, pn, frames, version=1, pad_to=1200):
    salt = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a" if version == 1 else "0dede3def700a6db819381be6e269dcbf9bd2ed9")
    pre = "quic " if version == 1 else "quicv2 "
    init = hkdf_extract(salt, dcid)
    cs = hkdf_expand_label(init, "client in", 32)
    key, iv, hp = (hkdf_expand_label(cs, pre + "key", 16), hkdf_expand_label(cs, pre + "iv", 12), hkdf_expand_label(cs, pre + "hp", 16))
    pn_len = 4
    first = (0xC0 if version == 1 else 0xD0) | (pn_len - 1)
    ver = struct.pack("!I", 1 if version == 1 else 0x6B3343CF)
    hdr_wo_len = bytes([first]) + ver + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid + b"\x00"
    payload = frames
    # length field: 2-byte varint
    length = pn_len + len(payload) + 16
    if pad_to:
        need = pad_to - (len(hdr_wo_len) + 2 + length)
        if need > 0:
            payload = payload + b"\0" * need
            length += need
    header = hdr_wo_len + struct.pack("!H", 0x4000 | length) + struct.pack("!I", pn)
    nonce = bytearray(iv)
    for i in range(8):
        nonce[-1 - i] ^= (pn >> (8 * i)) & 0xFF
    ct = AESGCM(key).encrypt(bytes(nonce), payload, header)
    pn_off = len(header) - pn_len
    sample = ct[4 - pn_len:4 - pn_len + 16]
    enc = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    mask = enc.update(sample) + enc.finalize()
    h = bytearray(header)
    h[0] ^= mask[0] & 0x0F
    for i in range(pn_len):
        h[pn_off + i] ^= mask[1 + i]
    return bytes(h) + ct, (key, iv, hp)


def varint(v):
    if v < 64:
        return bytes([v])
    if v < 16384:
        return struct.pack("!H", 0x4000 | v)
    return struct.pack("!I", 0x80000000 | v)


def crypto_frame(offset, data):
    return b"\x06" + varint(offset) + varint(len(data)) + data


RFC9001_CH = bytes.fromhex(
    "010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c"
    "00000413011302010000c000000010000e00000b6578616d706c652e636f6dff01000100000a"
    "00080006001d0017001800100007000504616c706e000500050100000000003300260024001d"
    "00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b0003"
    "020304000d0010000e0403050306030203080408050806002d00020101001c00024001003900"
    "320408ffffffffffffffff05048000ffff07048000ffff0801100104800075300901100f0883"
    "94c8f03e51570806048000ffff")


def make_synthetic():
    # 1. classic single-segment TLS 1.3 CH with GREASE, x25519 only
    hs = client_hello("example.org", ["h2", "http/1.1"], [0x0A0A, 0x001D, 0x0017, 0x0018], [(0x0A0A, 1), (0x001D, 32)],
                      CHROME_CIPHERS, CHROME_SIGALGS, seed="plain")
    tcp_session("tls13_single.pcap", record(hs))

    # 2. kyber: X25519MLKEM768 key share (1216 bytes) -> CH spans two segments; DPI RST with foreign TTL/IPID,
    #    arriving much faster than the server RTT
    hs = client_hello("blocked.example", ["h2", "http/1.1"], [0x5A5A, 0x11EC, 0x001D, 0x0017, 0x0018],
                      [(0x5A5A, 1), (0x11EC, 1216), (0x001D, 32)], CHROME_CIPHERS, CHROME_SIGALGS,
                      extra=[(0x0015, b"\0" * 32)], seed="kyber")
    tcp_session("tls13_kyber_rst.pcap", record(hs), mss=1400, rst=(250, 12345, 0.001))

    # 3. ECH outer hello, no GREASE, no ALPN, server RST with matching TTL (a real server reset)
    ech = b"\x00\x00\x01\x00\x01\x42\x00\x20" + det_bytes("ech:enc", 32) + struct.pack("!H", 144) + det_bytes("ech:payload", 144)
    hs = client_hello("cloudflare-ech.com", [], [0x001D, 0x0017], [(0x001D, 32)], [0x1301, 0x1303, 0x1302],
                      [0x0403, 0x0804], grease=False, ech=ech, seed="ech")
    tcp_session("tls13_ech_server_rst.pcap", record(hs), rst=(52, 0, 0.200))

    # 4. no SNI, ALPN http/1.1, the CH split over two TLS records
    body = client_hello(None, ["http/1.1"], [0x0017], [(0x0017, 65)], [0xC02F, 0xC030, 0x009C], [0x0401, 0x0501],
                        grease=False, seed="nosni")
    rec = record(body[:60]) + record(body[60:])
    tcp_session("tls_nosni_two_records.pcap", rec)

    # 5. QUIC v1 RFC 9001 Appendix A client Initial (same DCID, CH from the RFC)
    pkt, _ = quic_client_initial(bytes.fromhex("8394c8f03e515708"), b"", 2, crypto_frame(0, RFC9001_CH))
    write_pcap(os.path.join(OUT, "quic_rfc9001.pcap"), [(1700000100.0, udp(CLIENT, SERVER, 54321, 443, pkt))])

    # 6. QUIC v1, kyber CH split over two Initial packets, the CRYPTO frames in reverse order (Chrome style)
    hs = client_hello("www.youtube.com", ["h3"], [0x2A2A, 0x11EC, 0x001D, 0x0017], [(0x2A2A, 1), (0x11EC, 1216), (0x001D, 32)],
                      [0x1301, 0x1302, 0x1303], CHROME_SIGALGS, extra=[(0x0039, b"\x01\x04\x80\x00\xea\x60")], seed="quickyber")
    cut = 900
    dcid = det_bytes("quic:dcid", 8)
    scid = b""
    p1, _ = quic_client_initial(dcid, scid, 1, crypto_frame(cut, hs[cut:]) + b"\x01")
    p2, _ = quic_client_initial(dcid, scid, 2, crypto_frame(0, hs[:cut]))
    write_pcap(os.path.join(OUT, "quic_kyber_two_initials.pcap"),
               [(1700000200.0, udp(CLIENT, SERVER, 55555, 443, p1)), (1700000200.0001, udp(CLIENT, SERVER, 55555, 443, p2))])

    # 7. QUIC v2 (RFC 9369) single Initial
    hs = client_hello("v2.example.net", ["h3"], [0x001D], [(0x001D, 32)], [0x1301], [0x0403], grease=False,
                      extra=[(0x0039, b"\x01\x04\x80\x00\xea\x60")], seed="quicv2")
    pkt, _ = quic_client_initial(det_bytes("quic2:dcid", 8), det_bytes("quic2:scid", 4), 0, crypto_frame(0, hs), version=2)
    write_pcap(os.path.join(OUT, "quic_v2.pcap"), [(1700000300.0, udp(CLIENT, SERVER, 56565, 443, pkt))])


def make_live():
    tmp = tempfile.mkdtemp()
    key, crt = os.path.join(tmp, "k.pem"), os.path.join(tmp, "c.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt,
                    "-days", "1", "-subj", "/CN=localhost"], check=True, capture_output=True)
    for name, curl_args in [("live_curl_tls13.pcap", ["--tlsv1.3"]), ("live_curl_tls12.pcap", ["--tls-max", "1.2"])]:
        srv = subprocess.Popen(["openssl", "s_server", "-quiet", "-accept", "48443", "-key", key, "-cert", crt, "-www"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        dump = subprocess.Popen(["tcpdump", "-i", "lo", "-U", "-w", os.path.join(OUT, name), "tcp port 48443"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.5)
        subprocess.run(["curl", "-sk", "--noproxy", "*", "--http1.1", *curl_args, "--resolve", "test.local:48443:127.0.0.1",
                        "https://test.local:48443/"], capture_output=True)
        time.sleep(1)
        dump.terminate()
        dump.wait()
        srv.terminate()
        srv.wait()
    # a real browser hello: the reference for ClientHelloBuilder's "chrome141" spec
    chrome = os.environ.get("ZT_CHROMIUM", "/opt/pw-browsers/chromium-1194/chrome-linux/chrome")
    if os.path.exists(chrome):
        srv = subprocess.Popen(["openssl", "s_server", "-quiet", "-accept", "48443", "-key", key, "-cert", crt, "-www"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        dump = subprocess.Popen(["tcpdump", "-i", "lo", "-U", "-w", os.path.join(OUT, "live_chromium141.pcap"), "tcp port 48443"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.5)
        subprocess.run([chrome, "--headless=new", "--no-sandbox", "--disable-gpu", "--no-proxy-server",
                        "--host-resolver-rules=MAP chrome.test 127.0.0.1", "--ignore-certificate-errors", "--dump-dom",
                        "https://chrome.test:48443/"], capture_output=True, timeout=30)
        time.sleep(1)
        dump.terminate()
        dump.wait()
        srv.terminate()
        srv.wait()
    shutil.rmtree(tmp)


FIELDS = ["frame.number", "ip.src", "tcp.srcport", "udp.srcport", "ip.ttl", "ip.id",
          "tls.handshake.extensions_server_name", "tls.handshake.ja4", "tls.handshake.ja4_r", "tls.handshake.ja3",
          "tls.handshake.ja3_full", "tls.handshake.extensions_alpn_str", "tls.handshake.extensions.supported_version",
          "tls.handshake.extensions_key_share_group", "tcp.flags.reset"]


def reference(path):
    cmd = ["tshark", "-r", path, "-o", "tcp.desegment_tcp_streams:TRUE", "-T", "fields", "-E", "separator=\t",
           "-E", "occurrence=a", "-E", "aggregator=,"]
    for f in FIELDS:
        cmd += ["-e", f]
    out = subprocess.run(cmd, check=True, capture_output=True, text=True).stdout
    hellos, rsts = [], []
    for line in out.splitlines():
        v = dict(zip(FIELDS, line.split("\t")))
        if v.get("tls.handshake.ja4"):
            hellos.append({
                "frame": int(v["frame.number"]),
                "sni": v["tls.handshake.extensions_server_name"] or None,
                "ja4": v["tls.handshake.ja4"],
                "ja4_r": v["tls.handshake.ja4_r"],
                "ja3": v["tls.handshake.ja3"],
                "ja3_full": v["tls.handshake.ja3_full"],
                "alpn": [x for x in v["tls.handshake.extensions_alpn_str"].split(",") if x],
                "key_share_groups": [int(x, 0) for x in v["tls.handshake.extensions_key_share_group"].split(",") if x],
            })
        if v.get("tcp.flags.reset") in ("1", "True"):
            rsts.append({"frame": int(v["frame.number"]), "ttl": int(v["ip.ttl"]), "ip_id": int(v["ip.id"], 0)})
    return {"tshark": subprocess.run(["tshark", "--version"], capture_output=True, text=True).stdout.splitlines()[0],
            "client_hellos": hellos, "rsts": rsts}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true", help="re-make the live loopback captures (root)")
    a = ap.parse_args()
    os.makedirs(OUT, exist_ok=True)
    make_synthetic()
    if a.live:
        make_live()
    expected = {}
    for name in sorted(os.listdir(OUT)):
        if name.endswith((".pcap", ".pcapng")):
            expected[name] = reference(os.path.join(OUT, name))
    with open(os.path.join(OUT, "expected.json"), "w") as f:
        json.dump(expected, f, indent=2, sort_keys=True)
        f.write("\n")
    for k, v in expected.items():
        print(k, [(h["sni"], h["ja4"]) for h in v["client_hellos"]], v["rsts"])


if __name__ == "__main__":
    sys.exit(main())
