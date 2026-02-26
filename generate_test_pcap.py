#!/usr/bin/env python3
"""Generate test.pcap with all 12 required test cases for Argus.

Cases cover DNS, HTTP, and TLS traffic on both standard and non-standard ports,
including INTERNAL domain detection and AUTOMATION user-agent detection.
"""

import struct
from datetime import datetime
from scapy.all import IP, TCP, UDP, Raw, DNS, DNSQR, wrpcap, Ether

# Base timestamp: 2025-02-04 13:14:24.000000
BASE_TS = 1738682064.0
SRC = "192.168.190.128"


def make_dns(src, dst, sport, dport, qname, ts):
    """Craft a DNS A record query packet."""
    pkt = (IP(src=src, dst=dst) /
           UDP(sport=sport, dport=dport) /
           DNS(rd=1, qd=DNSQR(qname=qname, qtype="A")))
    pkt.time = ts
    return pkt


def make_http(src, dst, sport, dport, method, host, path, user_agent, ts):
    """Craft an HTTP request packet with raw payload."""
    request_line = f"{method} {path} HTTP/1.1\r\n"
    headers = f"Host: {host}\r\n"
    if user_agent:
        headers += f"User-Agent: {user_agent}\r\n"
    headers += "Accept: */*\r\n"
    headers += "Connection: close\r\n"
    payload = (request_line + headers + "\r\n").encode()

    pkt = (IP(src=src, dst=dst) /
           TCP(sport=sport, dport=dport, flags="PA", seq=1, ack=1) /
           Raw(load=payload))
    pkt.time = ts
    return pkt


def make_tls_client_hello(src, dst, sport, dport, server_name, ts):
    """Craft a TLS ClientHello packet with optional SNI.

    Builds the ClientHello manually as raw bytes to avoid Scapy TLS layer
    dependency issues. This ensures the packet is a valid TLS record.
    """
    # Build extensions
    extensions = b""

    if server_name:
        # SNI extension (type 0x0000)
        hostname = server_name.encode()
        # ServerName entry: type(1) + length(2) + name
        sn_entry = struct.pack("!BH", 0, len(hostname)) + hostname
        # ServerNameList: length(2) + entries
        sn_list = struct.pack("!H", len(sn_entry)) + sn_entry
        # Extension: type(2) + length(2) + data
        extensions += struct.pack("!HH", 0x0000, len(sn_list)) + sn_list

    # Supported Versions extension (type 0x002b) - TLS 1.2
    sv_data = b"\x02\x03\x03"  # 2 bytes list, TLS 1.2 (0x0303)
    extensions += struct.pack("!HH", 0x002b, len(sv_data)) + sv_data

    # ClientHello body
    client_hello_body = b""
    client_hello_body += struct.pack("!H", 0x0303)  # Client version TLS 1.2
    client_hello_body += b"\x00" * 32  # Random (32 bytes)
    client_hello_body += b"\x00"  # Session ID length = 0
    # Cipher suites (2 entries)
    client_hello_body += struct.pack("!H", 4)  # 2 cipher suites * 2 bytes
    client_hello_body += struct.pack("!HH", 0x1301, 0x00ff)  # TLS_AES_128_GCM, renegotiation
    client_hello_body += b"\x01\x00"  # Compression methods: 1 method, null
    # Extensions
    client_hello_body += struct.pack("!H", len(extensions))
    client_hello_body += extensions

    # Handshake header: type(1) + length(3)
    handshake = struct.pack("!B", 0x01)  # ClientHello type
    handshake += struct.pack("!I", len(client_hello_body))[1:]  # 3-byte length
    handshake += client_hello_body

    # TLS record header: content_type(1) + version(2) + length(2)
    tls_record = struct.pack("!BHH", 0x16, 0x0301, len(handshake))
    tls_record += handshake

    pkt = (IP(src=src, dst=dst) /
           TCP(sport=sport, dport=dport, flags="PA", seq=1, ack=1) /
           Raw(load=tls_record))
    pkt.time = ts
    return pkt


packets = []

# --- DNS Cases ---

# 1. DNS standard port - normal domain
packets.append(make_dns(
    SRC, "8.8.8.8", 35706, 53,
    "www.cs.stonybrook.edu", BASE_TS + 1.398317))

# 2. DNS non-standard port - normal domain
packets.append(make_dns(
    SRC, "1.1.1.1", 41234, 5353,
    "www.example.com", BASE_TS + 2.112345))

# 3. DNS standard port - INTERNAL (.local)
packets.append(make_dns(
    SRC, "192.168.190.1", 43054, 53,
    "esxi1.local", BASE_TS + 3.398317))

# 4. DNS non-standard port - INTERNAL (.corp)
packets.append(make_dns(
    SRC, "10.0.0.1", 44000, 1053,
    "db.corp", BASE_TS + 4.223456))

# --- HTTP Cases ---

# 5. HTTP standard port - normal GET
packets.append(make_http(
    SRC, "23.185.0.4", 36239, 80,
    "GET", "www.cs.stonybrook.edu", "/~cse363/",
    "Mozilla/5.0 (X11; Linux x86_64)", BASE_TS + 9.224487))

# 6. HTTP non-standard port - normal GET
packets.append(make_http(
    SRC, "93.184.216.34", 37000, 8080,
    "GET", "www.example.com", "/index.html",
    "Mozilla/5.0 (X11; Linux x86_64)", BASE_TS + 10.334567))

# 7. HTTP standard port - AUTOMATION (curl)
packets.append(make_http(
    SRC, "104.18.27.120", 41239, 80,
    "POST", "api.example.com", "/api/data",
    "curl/8.11.1", BASE_TS + 11.445678))

# 8. HTTP non-standard port - AUTOMATION (python-requests)
packets.append(make_http(
    SRC, "172.16.0.50", 42000, 9090,
    "PUT", "internal.example.com", "/upload",
    "python-requests/2.31.0", BASE_TS + 12.556789))

# --- TLS Cases ---

# 9. TLS standard port - with SNI
packets.append(make_tls_client_hello(
    SRC, "142.250.80.46", 59330, 443,
    "google.com", BASE_TS + 0.494045))

# 10. TLS non-standard port - with SNI
packets.append(make_tls_client_hello(
    SRC, "172.253.63.108", 58000, 993,
    "imap.gmail.com", BASE_TS + 5.667890))

# 11. TLS standard port - NO SNI
packets.append(make_tls_client_hello(
    SRC, "104.244.42.193", 37741, 443,
    None, BASE_TS + 6.778901))

# 12. TLS non-standard port - NO SNI
packets.append(make_tls_client_hello(
    SRC, "192.168.190.5", 38000, 8443,
    None, BASE_TS + 7.889012))

# Sort by timestamp for natural ordering
packets.sort(key=lambda p: float(p.time))

wrpcap("test.pcap", packets)
print(f"Generated test.pcap with {len(packets)} packets")
for i, pkt in enumerate(packets, 1):
    proto = "DNS" if pkt.haslayer(UDP) else ("HTTP/TLS" if pkt.haslayer(TCP) else "?")
    ts = datetime.fromtimestamp(float(pkt.time)).strftime("%H:%M:%S.%f")
    dst_port = pkt[UDP].dport if pkt.haslayer(UDP) else pkt[TCP].dport
    print(f"  {i:2d}. [{ts}] {proto:8s} -> port {dst_port}")
