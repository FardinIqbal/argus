# Architectural Decision Records

Each entry documents a non-obvious engineering choice, its alternatives, and why I picked what I picked.

---

## ADR 1: Layered fallback parsing (Scapy first, then manual binary)

**Status:** accepted

**Context:**
Each protocol could be parsed by:

1. **Scapy's high-level dissectors only**: clean, but Scapy does not auto-dissect on non-standard ports.
2. **Manual binary parsing only**: works on any port, but reimplements logic Scapy already has.
3. **Layered fallback** (this design): try Scapy first; fall back to manual parsing if Scapy did not parse.

**Decision:**
Layered fallback.

**Consequences:**

- Pro: Scapy handles the common case (standard ports) cleanly and quickly.
- Pro: manual parsing handles the long tail (non-standard ports, malformed packets).
- Pro: when Scapy is upgraded and improves dissection, Argus inherits the improvement automatically.
- Con: two code paths per protocol means more surface area for bugs.
- Con: the fallback path is harder to debug because Scapy already returned `None`.

The fallback is the entire point of Argus: catching protocols on non-standard ports. Without it, the project is just a Scapy wrapper.

---

## ADR 2: Hand-coded TLS binary parser instead of cryptography library

**Status:** accepted

**Context:**
Extracting SNI from a TLS ClientHello requires parsing the binary structure. Two options:

1. **Use a cryptography library** that exposes ClientHello fields (e.g., openssl bindings).
2. **Hand-code a binary parser** (this design): walk the structure with `struct.unpack`.

**Decision:**
Hand-coded.

**Consequences:**

- Pro: educational. Implementing the parser teaches the TLS handshake structure better than using a library.
- Pro: no dependency on a heavy cryptography stack.
- Pro: direct control over error handling. Malformed packets do not crash.
- Con: more code (~25 lines).
- Con: less battle-tested than a library that has parsed billions of ClientHellos.

For a study project focused on protocol detection, hand-coded is the right call. For a security tool that needs to be bulletproof against malformed input, a library would be safer.

---

## ADR 3: Substring matching for User-Agent automation detection

**Status:** accepted

**Context:**
Detecting automation tools by User-Agent. Two options:

1. **Substring match** (this design): check if any of 8 known prefixes appear in the User-Agent string.
2. **Regex**: more flexible patterns, but slower.

**Decision:**
Substring.

**Consequences:**

- Pro: fast. `in` operator on Python strings is C-implemented.
- Pro: simple. No regex compilation, no escape characters.
- Pro: the patterns are distinct enough that substring is sufficient.
- Con: cannot match more nuanced patterns (version requirements, optional fields).

For the eight target tools, substring is sufficient. Adding more sophisticated matching is a one-line change to use `re.search` if needed.

---

## ADR 4: Internal TLD list is hardcoded

**Status:** accepted

**Context:**
The list of internal TLDs (`.local`, `.corp`, `.internal`) is hardcoded. Two options:

1. **Hardcoded** (this design): the list is a tuple in the source file.
2. **Configurable**: load from a config file or command-line flag.

**Decision:**
Hardcoded.

**Consequences:**

- Pro: simple. No config file, no CLI flag.
- Pro: documented in source. Anyone reading argus.py knows what gets flagged.
- Con: extending the list requires editing source.
- Con: cannot adjust per-environment (a corporate environment using `.intranet` would need a code change).

For a study project, hardcoded is fine. The three TLDs cover the most common cases (RFC 6762 `.local`, common corporate `.corp`, and the placeholder `.internal`). Adding more is a one-line edit.

---

## ADR 5: No IPv6 support yet

**Status:** accepted, deliberately deferred

**Context:**
Argus only inspects IPv4 packets. The dispatch loop checks for the `IP` layer; `IPv6` is not currently handled. Two options:

1. **IPv4 only** (this design): keeps the dispatch simple.
2. **Both IPv4 and IPv6**: add IPv6 detection alongside IPv4.

**Decision:**
IPv4 only for now.

**Consequences:**

- Pro: simpler dispatch logic.
- Pro: matches the test pcap (all IPv4 traffic).
- Con: IPv6 traffic is silently dropped. In a real network, this can be a significant fraction of traffic.

Future work: add `pkt.haslayer(IPv6)` alongside `pkt.haslayer(IP)` and adjust src/dst extraction. The protocol handlers (DNS, HTTP, TLS) are layer-agnostic; only the address extraction needs updating.

---

## ADR 6: Per-packet output, no aggregation

**Status:** accepted

**Context:**
Argus emits one line per detected packet. Two options:

1. **Per-packet** (this design): emit immediately, no aggregation.
2. **Aggregated** (e.g., one line per session): combine packets that belong to the same flow.

**Decision:**
Per-packet.

**Consequences:**

- Pro: simple. No state machine, no flow tracking.
- Pro: easy to grep and pipe to other tools.
- Pro: real-time output. Each packet appears as it is processed.
- Con: noisy. A long HTTP request with multiple headers may show only the first packet (which is fine for the use case).
- Con: cannot easily aggregate across a session (e.g., "this client made 50 requests").

For Argus's purpose (protocol detection on non-standard ports), per-packet is the right granularity. Flow aggregation is a separate analysis concern.
