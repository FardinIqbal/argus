#!/usr/bin/env python3
"""Generate test.pcap with all 12 required test cases for Argus.

Covers DNS, HTTP, and TLS on standard and non-standard ports,
with INTERNAL and AUTOMATION detection cases.
"""

import struct
from datetime import datetime
from scapy.all import IP, TCP, UDP, Raw, DNS, DNSQR, wrpcap

BASE_TS = 1738682064.0  # 2025-02-04 13:14:24 UTC
SRC = "192.168.190.128"


def dns(dst, sport, dport, qname, ts_offset):
    pkt = (IP(src=SRC, dst=dst) /
           UDP(sport=sport, dport=dport) /
           DNS(rd=1, qd=DNSQR(qname=qname, qtype="A")))
    pkt.time = BASE_TS + ts_offset
    return pkt


def http(dst, sport, dport, method, host, path, ua, ts_offset):
    lines = [f"{method} {path} HTTP/1.1",
             f"Host: {host}",
             f"User-Agent: {ua}" if ua else None,
             "Accept: */*",
             "Connection: close",
             "", ""]
    payload = "\r\n".join(l for l in lines if l is not None).encode()
    pkt = (IP(src=SRC, dst=dst) /
           TCP(sport=sport, dport=dport, flags="PA", seq=1, ack=1) /
           Raw(load=payload))
    pkt.time = BASE_TS + ts_offset
    return pkt


def tls_hello(dst, sport, dport, server_name, ts_offset):
    """Craft a TLS ClientHello with optional SNI, built from raw bytes."""
    ext = b""
    if server_name:
        hostname = server_name.encode()
        sn_entry = struct.pack("!BH", 0, len(hostname)) + hostname
        sn_list = struct.pack("!H", len(sn_entry)) + sn_entry
        ext += struct.pack("!HH", 0x0000, len(sn_list)) + sn_list

    # Supported versions extension (TLS 1.2)
    sv = b"\x02\x03\x03"
    ext += struct.pack("!HH", 0x002b, len(sv)) + sv

    body = b"".join([
        struct.pack("!H", 0x0303),      # version: TLS 1.2
        b"\x00" * 32,                    # random
        b"\x00",                         # session ID length
        struct.pack("!HHH", 4, 0x1301, 0x00ff),  # cipher suites
        b"\x01\x00",                     # compression: null
        struct.pack("!H", len(ext)),     # extensions length
        ext,
    ])

    handshake = struct.pack("!B", 0x01) + struct.pack("!I", len(body))[1:] + body
    record = struct.pack("!BHH", 0x16, 0x0301, len(handshake)) + handshake

    pkt = (IP(src=SRC, dst=dst) /
           TCP(sport=sport, dport=dport, flags="PA", seq=1, ack=1) /
           Raw(load=record))
    pkt.time = BASE_TS + ts_offset
    return pkt


# --- 12 test cases: 4 DNS, 4 HTTP, 4 TLS ---

packets = sorted([
    # DNS standard/non-standard, normal/INTERNAL
    dns("8.8.8.8",         35706, 53,   "www.cs.stonybrook.edu", 1.398317),
    dns("1.1.1.1",         41234, 5353, "www.example.com",       2.112345),
    dns("192.168.190.1",   43054, 53,   "esxi1.local",           3.398317),
    dns("10.0.0.1",        44000, 1053, "db.corp",               4.223456),

    # HTTP standard/non-standard, normal/AUTOMATION
    http("23.185.0.4",     36239, 80,   "GET",  "www.cs.stonybrook.edu", "/~cse363/",
         "Mozilla/5.0 (X11; Linux x86_64)",  9.224487),
    http("93.184.216.34",  37000, 8080, "GET",  "www.example.com",       "/index.html",
         "Mozilla/5.0 (X11; Linux x86_64)",  10.334567),
    http("104.18.27.120",  41239, 80,   "POST", "api.example.com",       "/api/data",
         "curl/8.11.1",                      11.445678),
    http("172.16.0.50",    42000, 9090, "PUT",  "internal.example.com",  "/upload",
         "python-requests/2.31.0",           12.556789),

    # TLS standard/non-standard, with SNI/NO SNI
    tls_hello("142.250.80.46",  59330, 443,  "google.com",     0.494045),
    tls_hello("172.253.63.108", 58000, 993,  "imap.gmail.com", 5.667890),
    tls_hello("104.244.42.193", 37741, 443,  None,             6.778901),
    tls_hello("192.168.190.5",  38000, 8443, None,             7.889012),
], key=lambda p: float(p.time))

wrpcap("test.pcap", packets)
print(f"Generated test.pcap with {len(packets)} packets")
for i, pkt in enumerate(packets, 1):
    proto = "DNS" if pkt.haslayer(UDP) else "HTTP/TLS"
    ts = datetime.fromtimestamp(float(pkt.time)).strftime("%H:%M:%S.%f")
    port = pkt[UDP].dport if pkt.haslayer(UDP) else pkt[TCP].dport
    print(f"  {i:2d}. [{ts}] {proto:8s} -> port {port}")
