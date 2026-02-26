#!/usr/bin/env python3
"""Argus - passive network sniffer for HTTP, TLS, and DNS traffic.

Detects and parses protocols regardless of port number.
"""

import sys
import struct
import argparse
from datetime import datetime

from scapy.all import sniff, Raw, TCP, UDP, IP, DNS, DNSQR
from scapy.layers.http import HTTPRequest

try:
    from scapy.layers.tls.record import TLS
    from scapy.layers.tls.handshake import TLSClientHello
    from scapy.layers.tls.extensions import TLS_Ext_ServerName
    _TLS = True
except ImportError:
    _TLS = False

INTERNAL_TLDS = (".local", ".corp", ".internal")
AUTOMATION_PATTERNS = ("curl/", "wget/", "python-requests", "python-urllib",
                       "python-httpx", "libwww-perl", "go-http-client", "httpie")
HTTP_METHODS = (b"GET ", b"POST ", b"PUT ")


def _decode(val):
    """Decode bytes to str, None to empty string."""
    if val is None:
        return ""
    return val.decode(errors="replace") if isinstance(val, bytes) else str(val)


def _emit(pkt, proto, details):
    """Format and print one output line."""
    ts = datetime.fromtimestamp(float(pkt.time)).strftime("%Y-%m-%d %H:%M:%S.%f")
    t = pkt[UDP] if pkt.haslayer(UDP) else pkt[TCP]
    print(f"{ts} {proto:4s} {pkt[IP].src}:{t.sport} -> "
          f"{pkt[IP].dst}:{t.dport} {details}", flush=True)


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

def handle_dns(pkt):
    """Parse DNS A record queries."""
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        dns = pkt[DNS]
    elif pkt.haslayer(Raw):
        raw = pkt[Raw].load
        if len(raw) < 12:
            return None
        try:
            dns = DNS(raw)
        except Exception:
            return None
    else:
        return None

    if dns.qr != 0 or not dns.qd or dns.qd.qtype not in (1, 28):
        return None

    name = _decode(dns.qd.qname).rstrip(".")
    if any(name.lower().endswith(tld) for tld in INTERNAL_TLDS):
        return name + " INTERNAL"
    return name


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

def handle_http(pkt):
    """Parse HTTP GET/POST/PUT requests."""
    if pkt.haslayer(HTTPRequest):
        return _http_fields(pkt[HTTPRequest])

    if not pkt.haslayer(Raw):
        return None
    raw = pkt[Raw].load
    if not any(raw.startswith(m) for m in HTTP_METHODS):
        return None
    try:
        return _http_fields(HTTPRequest(raw))
    except Exception:
        return _http_raw(raw)


def _http_fields(http):
    """Extract fields from a Scapy HTTPRequest layer."""
    method = _decode(http.Method)
    if method not in ("GET", "POST", "PUT"):
        return None
    return _http_result(method,
                        _decode(getattr(http, "Host", b"")),
                        _decode(http.Path),
                        _decode(getattr(http, "User_Agent", None)))


def _http_raw(data):
    """Fallback: parse HTTP from raw bytes."""
    try:
        lines = data.decode("ascii", errors="replace").split("\r\n")
        method, path = lines[0].split(" ", 2)[:2]
        hdrs = {}
        for line in lines[1:]:
            if not line:
                break
            if ": " in line:
                k, v = line.split(": ", 1)
                hdrs[k.lower()] = v
        return _http_result(method, hdrs.get("host", ""), path,
                            hdrs.get("user-agent", ""))
    except Exception:
        return None


def _http_result(method, host, path, ua):
    """Assemble the HTTP detail string."""
    result = f"{host} {method} {path}"
    if ua and any(p in ua.lower() for p in AUTOMATION_PATTERNS):
        result += f" AUTOMATION {ua}"
    return result


# ---------------------------------------------------------------------------
# TLS
# ---------------------------------------------------------------------------

def handle_tls(pkt):
    """Parse TLS ClientHello, extract SNI."""
    if _TLS and pkt.haslayer(TLSClientHello):
        return _sni_layer(pkt[TLSClientHello])

    if not pkt.haslayer(Raw):
        return None
    raw = pkt[Raw].load
    if len(raw) < 6 or raw[0] != 0x16 or raw[1] != 0x03 or raw[5] != 0x01:
        return None

    if _TLS:
        try:
            tls = TLS(raw)
            if tls.haslayer(TLSClientHello):
                return _sni_layer(tls[TLSClientHello])
        except Exception:
            pass

    return _sni_raw(raw)


def _sni_layer(ch):
    """Extract SNI from a parsed TLSClientHello."""
    if ch.ext:
        for ext in ch.ext:
            if isinstance(ext, TLS_Ext_ServerName) and ext.servernames:
                name = _decode(ext.servernames[0].servername)
                if name:
                    return name
    return "NO SNI"


def _sni_raw(data):
    """Walk raw ClientHello bytes to find SNI."""
    try:
        pos = 43                                                     # record(5) + handshake(4) + version(2) + random(32)
        pos += 1 + data[pos]                                         # session ID
        pos += 2 + struct.unpack("!H", data[pos:pos + 2])[0]        # cipher suites
        pos += 1 + data[pos]                                         # compression
        ext_end = pos + 2 + struct.unpack("!H", data[pos:pos + 2])[0]
        pos += 2

        while pos + 4 <= ext_end:
            etype, elen = struct.unpack("!HH", data[pos:pos + 4])
            pos += 4
            if etype == 0:                                           # server_name
                if data[pos + 2] == 0:                               # host_name type
                    nlen = struct.unpack("!H", data[pos + 3:pos + 5])[0]
                    return data[pos + 5:pos + 5 + nlen].decode(errors="replace")
                return "NO SNI"
            pos += elen

        return "NO SNI"
    except Exception:
        return "NO SNI"


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

HANDLERS = [
    (UDP, handle_dns,  "DNS"),
    (TCP, handle_http, "HTTP"),
    (TCP, handle_tls,  "TLS"),
]


def process_packet(pkt):
    """Route each packet to the appropriate protocol handler."""
    if not pkt.haslayer(IP):
        return
    for layer, handler, proto in HANDLERS:
        if pkt.haslayer(layer):
            result = handler(pkt)
            if result is not None:
                _emit(pkt, proto, result)
                return


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Argus - passive network sniffer",
        usage="%(prog)s [-i interface] [-r tracefile] [expression]")
    parser.add_argument("-i", dest="interface",
                        help="live capture interface (default: auto)")
    parser.add_argument("-r", dest="tracefile",
                        help="read from pcap file (overrides -i)")
    parser.add_argument("expression", nargs="*",
                        help="BPF filter expression")
    args = parser.parse_args()

    kwargs = {"prn": process_packet, "store": 0}
    if args.tracefile:
        kwargs["offline"] = args.tracefile
    elif args.interface:
        kwargs["iface"] = args.interface
    if args.expression:
        kwargs["filter"] = " ".join(args.expression)

    try:
        sniff(**kwargs)
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
