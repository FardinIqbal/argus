#!/usr/bin/env python3
"""argus.py - Passive network sniffer for HTTP, TLS ClientHello, and DNS traffic.

Supports port-independent protocol detection: recognizes HTTP, TLS, and DNS
traffic regardless of the destination port number used.

CSE 363: Offensive Security - Homework 1
"""

import sys
import struct
import argparse
from datetime import datetime

from scapy.all import sniff, Raw, TCP, UDP, IP, DNS, DNSQR, conf
from scapy.layers.http import HTTPRequest

# Load TLS layer for ClientHello parsing
try:
    from scapy.layers.tls.record import TLS
    from scapy.layers.tls.handshake import TLSClientHello
    from scapy.layers.tls.extensions import TLS_Ext_ServerName, ServerName
    TLS_AVAILABLE = True
except ImportError:
    TLS_AVAILABLE = False

# TLDs indicative of internal infrastructure
INTERNAL_TLDS = (".local", ".corp", ".internal")

# User-Agent substrings indicative of automation/scripts
AUTOMATION_PATTERNS = ("curl/", "wget/", "python-requests", "python-urllib",
                       "python-httpx", "libwww-perl", "go-http-client", "httpie")


def _decode(value):
    """Safely decode bytes to string."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return str(value)


def format_timestamp(pkt):
    """Convert packet timestamp to 'YYYY-MM-DD HH:MM:SS.ffffff' format."""
    ts = float(pkt.time)
    dt = datetime.fromtimestamp(ts)
    return dt.strftime("%Y-%m-%d %H:%M:%S.%f")


def format_line(pkt, proto, details):
    """Format an output line: TIMESTAMP PROTO SRC:SPORT -> DST:DPORT details"""
    timestamp = format_timestamp(pkt)
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst

    if pkt.haslayer(TCP):
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
    else:
        return None

    return f"{timestamp} {proto:4s} {src_ip}:{sport} -> {dst_ip}:{dport} {details}"


def is_internal(name):
    """Check if a domain name has an internal infrastructure TLD."""
    lower = name.lower()
    for tld in INTERNAL_TLDS:
        if lower.endswith(tld):
            return True
    return False


def is_automation(user_agent):
    """Check if a User-Agent string indicates automation/scripts."""
    if not user_agent:
        return False
    ua_lower = user_agent.lower()
    for pattern in AUTOMATION_PATTERNS:
        if pattern in ua_lower:
            return True
    return False


# ---------------------------------------------------------------------------
# DNS Detection & Extraction
# ---------------------------------------------------------------------------

def handle_dns(pkt):
    """Detect and parse DNS A record queries. Returns formatted details or None."""
    dns_layer = None

    # Case 1: Scapy auto-detected DNS (standard port 53)
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        dns_layer = pkt[DNS]
    # Case 2: Non-standard port - try parsing UDP payload as DNS
    elif pkt.haslayer(UDP) and pkt.haslayer(Raw):
        payload = pkt[Raw].load
        if len(payload) < 12:
            return None
        try:
            dns_layer = DNS(payload)
        except Exception:
            return None

    if dns_layer is None:
        return None

    # Only process queries (qr=0) with A record type (qtype=1)
    if dns_layer.qr != 0:
        return None
    if not dns_layer.qd:
        return None
    # Accept A records (qtype=1) and optionally AAAA (qtype=28)
    if dns_layer.qd.qtype not in (1, 28):
        return None

    qname = _decode(dns_layer.qd.qname)
    # Remove trailing dot
    if qname.endswith("."):
        qname = qname[:-1]

    result = qname
    if is_internal(qname):
        result += " INTERNAL"

    return result


# ---------------------------------------------------------------------------
# HTTP Detection & Extraction
# ---------------------------------------------------------------------------

def handle_http(pkt):
    """Detect and parse HTTP GET/POST/PUT requests. Returns formatted details or None."""
    method = None
    host = ""
    path = ""
    user_agent = ""

    # Case 1: Scapy auto-detected HTTPRequest (standard port 80)
    if pkt.haslayer(HTTPRequest):
        http = pkt[HTTPRequest]
        method = _decode(http.Method)
        if method not in ("GET", "POST", "PUT"):
            return None
        host = _decode(getattr(http, "Host", b""))
        path = _decode(http.Path)
        user_agent = _decode(getattr(http, "User_Agent", None))
    # Case 2: Non-standard port - check raw TCP payload
    elif pkt.haslayer(TCP) and pkt.haslayer(Raw):
        payload = pkt[Raw].load
        if not (payload.startswith(b"GET ") or payload.startswith(b"POST ") or
                payload.startswith(b"PUT ")):
            return None

        # Try Scapy's HTTP parser on raw bytes
        try:
            http = HTTPRequest(payload)
            method = _decode(http.Method)
            host = _decode(getattr(http, "Host", b""))
            path = _decode(http.Path)
            user_agent = _decode(getattr(http, "User_Agent", None))
        except Exception:
            # Fallback: manual parsing
            method, host, path, user_agent = _parse_http_manual(payload)

        if method is None or method not in ("GET", "POST", "PUT"):
            return None
    else:
        return None

    result = f"{host} {method} {path}"
    if is_automation(user_agent):
        result += f" AUTOMATION {user_agent}"

    return result


def _parse_http_manual(payload):
    """Manually parse an HTTP request from raw bytes."""
    try:
        text = payload.decode("ascii", errors="replace")
        lines = text.split("\r\n")
        parts = lines[0].split(" ", 2)
        method = parts[0]
        path = parts[1] if len(parts) > 1 else "/"

        headers = {}
        for line in lines[1:]:
            if ": " in line:
                key, val = line.split(": ", 1)
                headers[key.lower()] = val
            elif line == "":
                break

        host = headers.get("host", "")
        user_agent = headers.get("user-agent", "")
        return method, host, path, user_agent
    except Exception:
        return None, "", "", ""


# ---------------------------------------------------------------------------
# TLS Detection & Extraction
# ---------------------------------------------------------------------------

def handle_tls(pkt):
    """Detect TLS ClientHello and extract SNI. Returns hostname or 'NO SNI', or None."""
    if not pkt.haslayer(TCP):
        return None

    # Case 1: Scapy auto-detected TLSClientHello (standard port 443)
    if TLS_AVAILABLE and pkt.haslayer(TLSClientHello):
        return _extract_sni(pkt[TLSClientHello])

    # Case 2: Non-standard port - check raw TCP payload
    if not pkt.haslayer(Raw):
        return None

    payload = pkt[Raw].load
    if len(payload) < 6:
        return None

    # TLS record header check:
    # byte[0] = 0x16 (handshake)
    # byte[1] = 0x03 (SSL/TLS major version)
    # byte[2] = 0x00-0x04 (minor version: SSLv3.0 through TLS 1.3)
    # byte[5] = 0x01 (ClientHello handshake type)
    if (payload[0] != 0x16 or payload[1] != 0x03 or
            payload[2] not in (0x00, 0x01, 0x02, 0x03, 0x04) or
            payload[5] != 0x01):
        return None

    # Try Scapy's TLS parser
    if TLS_AVAILABLE:
        try:
            tls_pkt = TLS(payload)
            if tls_pkt.haslayer(TLSClientHello):
                return _extract_sni(tls_pkt[TLSClientHello])
        except Exception:
            pass

    # Fallback: manual SNI extraction from raw bytes
    return _extract_sni_manual(payload)


def _extract_sni(client_hello):
    """Extract SNI hostname from a TLSClientHello layer."""
    if client_hello.ext:
        for ext in client_hello.ext:
            if isinstance(ext, TLS_Ext_ServerName):
                if ext.servernames:
                    for sn in ext.servernames:
                        name = sn.servername
                        if isinstance(name, bytes):
                            name = name.decode(errors="replace")
                        if name:
                            return name
    return "NO SNI"


def _extract_sni_manual(payload):
    """Manually extract SNI from raw TLS ClientHello bytes."""
    try:
        # Skip TLS record header (5 bytes) and handshake header (4 bytes)
        # to reach ClientHello body
        pos = 5 + 4  # record header + handshake header

        if pos + 2 > len(payload):
            return "NO SNI"

        # Skip client version (2 bytes)
        pos += 2
        # Skip random (32 bytes)
        pos += 32

        if pos + 1 > len(payload):
            return "NO SNI"

        # Skip session ID
        session_id_len = payload[pos]
        pos += 1 + session_id_len

        if pos + 2 > len(payload):
            return "NO SNI"

        # Skip cipher suites
        cipher_suites_len = struct.unpack("!H", payload[pos:pos + 2])[0]
        pos += 2 + cipher_suites_len

        if pos + 1 > len(payload):
            return "NO SNI"

        # Skip compression methods
        comp_len = payload[pos]
        pos += 1 + comp_len

        if pos + 2 > len(payload):
            return "NO SNI"

        # Extensions length
        ext_len = struct.unpack("!H", payload[pos:pos + 2])[0]
        pos += 2
        ext_end = pos + ext_len

        # Parse extensions looking for SNI (type 0x0000)
        while pos + 4 <= ext_end and pos + 4 <= len(payload):
            ext_type = struct.unpack("!H", payload[pos:pos + 2])[0]
            ext_data_len = struct.unpack("!H", payload[pos + 2:pos + 4])[0]
            pos += 4

            if ext_type == 0x0000:  # server_name extension
                # SNI extension format:
                # 2 bytes: server name list length
                # 1 byte: name type (0 = hostname)
                # 2 bytes: name length
                # N bytes: hostname
                if pos + 5 <= len(payload):
                    name_type = payload[pos + 2]
                    name_len = struct.unpack("!H", payload[pos + 3:pos + 5])[0]
                    if name_type == 0 and pos + 5 + name_len <= len(payload):
                        hostname = payload[pos + 5:pos + 5 + name_len]
                        return hostname.decode(errors="replace")
                return "NO SNI"

            pos += ext_data_len

        return "NO SNI"
    except Exception:
        return "NO SNI"


# ---------------------------------------------------------------------------
# Packet Processing Callback
# ---------------------------------------------------------------------------

def process_packet(pkt):
    """Main callback for sniff(). Routes packets to protocol handlers."""
    if not pkt.haslayer(IP):
        return

    # UDP protocols: DNS
    if pkt.haslayer(UDP):
        details = handle_dns(pkt)
        if details is not None:
            line = format_line(pkt, "DNS", details)
            if line:
                print(line, flush=True)
            return

    # TCP protocols: HTTP, then TLS
    if pkt.haslayer(TCP):
        # Try HTTP first
        details = handle_http(pkt)
        if details is not None:
            line = format_line(pkt, "HTTP", details)
            if line:
                print(line, flush=True)
            return

        # Try TLS ClientHello
        details = handle_tls(pkt)
        if details is not None:
            line = format_line(pkt, "TLS", details)
            if line:
                print(line, flush=True)
            return


# ---------------------------------------------------------------------------
# CLI & Main
# ---------------------------------------------------------------------------

def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Argus - passive network sniffer for HTTP, TLS, and DNS traffic",
        usage="%(prog)s [-i interface] [-r tracefile] [expression]"
    )
    parser.add_argument("-i", dest="interface", default=None,
                        help="Network interface for live capture (default: auto-select)")
    parser.add_argument("-r", dest="tracefile", default=None,
                        help="Read packets from pcap tracefile (overrides -i)")
    parser.add_argument("expression", nargs="*",
                        help="BPF filter expression")

    args = parser.parse_args()
    args.expression = " ".join(args.expression) if args.expression else None
    return args


def main():
    args = parse_args()

    sniff_kwargs = {
        "prn": process_packet,
        "store": 0,
    }

    if args.tracefile:
        sniff_kwargs["offline"] = args.tracefile
    elif args.interface:
        sniff_kwargs["iface"] = args.interface

    if args.expression:
        sniff_kwargs["filter"] = args.expression

    try:
        sniff(**sniff_kwargs)
    except KeyboardInterrupt:
        sys.exit(0)
    except PermissionError:
        print("Error: Permission denied. Run with sudo for live capture.",
              file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError:
        print(f"Error: Tracefile '{args.tracefile}' not found.",
              file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
