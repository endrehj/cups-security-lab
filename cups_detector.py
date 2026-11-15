#!/usr/bin/env python3
import argparse
import csv
import ipaddress
import json
import logging
import math
import re
import socket
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from scapy.all import IP, IPv6, Raw, TCP, UDP, PcapReader, sniff

LOGGER = logging.getLogger("cups_detector")
BROWSE_RE = re.compile(
    r'^([0-9a-fA-F]{1,8})\s+(\d+)\s+(\S+)\s+"([^"]*)"\s+"([^"]*)"\s+"([^"]*)"\s*$'
)
HTTP_REQUEST_RE = re.compile(rb"(?:POST|GET) [^\r\n ]+ HTTP/1\.[01]\r\n")
PRINTER_PATH_RE = re.compile(rb"(?:POST|GET) /printers/")
CSV_FIELDS = ["timestamp", "severity", "category", "source", "destination", "details"]


def resolve_host(value):
    """Accept an IP literal or hostname (including Compose service names)."""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return socket.gethostbyname(value)


def parse_args():
    p = argparse.ArgumentParser(description=__doc__)
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--pcap", type=Path, help="Analyze an existing PCAP")
    mode.add_argument("--live", action="store_true", help="Capture packets in real time")
    p.add_argument("--iface", help="Interface for live capture (e.g. eth0)")
    p.add_argument("--trusted-advertiser", action="append", default=[],
                   metavar="HOST", help="Trusted CUPS advertiser; repeatable")
    p.add_argument("--trusted-printer", action="append", default=[],
                   metavar="HOST", help="Trusted IPP endpoint; repeatable")
    p.add_argument("--ipp-port", type=int, action="append", default=[],
                   help="Recognized IPP TCP port; repeatable (defaults: 631, 8631)")
    p.add_argument("--threshold", type=int, default=3,
                   help="Number of advertisements in window to flag (default: 3)")
    p.add_argument("--window", type=float, default=10,
                   help="Sliding window in seconds (default: 10)")
    p.add_argument("--callback-window", type=float, default=30,
                   help="Maximum advertisement-to-callback delay in seconds (default: 30)")
    p.add_argument("--output", type=Path, default=Path("evidence/cups_alerts.json"),
                   help="Output alert file (.json or .csv)")
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args()
    if (args.threshold < 2 or not math.isfinite(args.window) or args.window <= 0
            or not math.isfinite(args.callback_window) or args.callback_window <= 0):
        p.error("--threshold must be >= 2 and --window and --callback-window must be positive")
    if any(port < 1 or port > 65535 for port in args.ipp_port):
        p.error("IPP ports must be between 1 and 65535")
    if args.output.suffix.lower() not in (".json", ".csv"):
        p.error("--output must end in .json or .csv")
    try:
        args.trusted_advertiser = {resolve_host(x) for x in args.trusted_advertiser}
        args.trusted_printer = {resolve_host(x) for x in args.trusted_printer}
    except OSError as exc:
        p.error(f"Cannot resolve trusted host: {exc}")
    args.ipp_ports = set(args.ipp_port or [631, 8631])
    return args


class Detector:
    def __init__(self, args):
        self.args = args
        self.alerts = []
        self.count = 0
        self.advertisements = defaultdict(deque)
        self.advertised_endpoints = {}
        self.reported_flows = set()

    def alert(self, ts, severity, category, source, destination, details):
        item = {
            "timestamp": datetime.fromtimestamp(ts, timezone.utc).isoformat(),
            "severity": severity,
            "category": category,
            "source": source,
            "destination": destination,
            "details": details,
        }
        self.alerts.append(item)
        level = logging.INFO if severity == "INFO" else logging.WARNING
        LOGGER.log(level, "[%s] %s: %s -> %s | %s",
                   severity, category, source, destination, details)

    def handle_browse(self, ts, src, dst, data):
        # Include malformed announcements in the source rate, too.
        samples = self.advertisements[src]
        while samples and ts - samples[0] > self.args.window:
            samples.popleft()
        samples.append(ts)
        if len(samples) == self.args.threshold:
            self.alert(ts, "MEDIUM", "repeated_discovery", src, dst,
                       f"{len(samples)} browse announcements within {self.args.window:g}s")

        preview = data[:512].decode("utf-8", errors="replace").strip()
        if len(data) > 2048 or b"\x00" in data or b"\r" in data:
            self.alert(ts, "HIGH", "malformed_discovery", src, dst,
                       "Unexpected NUL/CR bytes or oversized discovery payload")
            return
        try:
            text = data.decode("utf-8").strip()
        except UnicodeDecodeError:
            self.alert(ts, "HIGH", "malformed_discovery", src, dst,
                       f"Discovery payload is not UTF-8: {preview[:100]!r}")
            return
        match = BROWSE_RE.fullmatch(text)
        if not match:
            self.alert(ts, "HIGH", "malformed_discovery", src, dst,
                       f"Unexpected legacy CUPS browse format: {preview[:120]!r}")
            return

        printer_type, state_str, uri, location, info, model = match.groups()
        state = int(state_str)
        if state not in (3, 4, 5):
            self.alert(ts, "MEDIUM", "unexpected_field", src, dst,
                       f"Unusual printer state {state}; expected 3, 4, or 5")
        try:
            parsed = urlsplit(uri)
            host = parsed.hostname
            port = parsed.port
            if (parsed.scheme not in ("http", "https") or not host or
                    not parsed.path.startswith("/printers/") or
                    parsed.username is not None or parsed.password is not None):
                raise ValueError("unusual URI scheme/path/credentials")
            if port is None:
                port = 443 if parsed.scheme == "https" else 80
            # Do not consult today's DNS when interpreting a historical capture.
            try:
                endpoint_ip = str(ipaddress.ip_address(host))
            except ValueError:
                endpoint_ip = resolve_host(host) if not self.args.pcap else None
            if endpoint_ip is not None:
                suspicious = (src not in self.args.trusted_advertiser
                              or endpoint_ip not in self.args.trusted_printer)
                self.advertised_endpoints[(dst, endpoint_ip, port)] = (ts, suspicious)
        except (ValueError, OSError) as exc:
            self.alert(ts, "HIGH", "unexpected_field", src, dst,
                       f"Invalid or unresolvable advertised URI {uri!r}: {exc}")

        if src not in self.args.trusted_advertiser:
            self.alert(ts, "HIGH", "unauthorized_advertisement", src, dst,
                       f"Untrusted advertiser announced {uri} ({info}; {location}; {model}; type={printer_type})")

    def handle_tcp(self, ts, src, dst, tcp, payload):
        # SYN without ACK identifies an attempted TCP connection, not an established one.
        if tcp.flags & 0x02 and not tcp.flags & 0x10:
            dst_port = int(tcp.dport)
            self.advertised_endpoints = {
                key: record for key, record in self.advertised_endpoints.items()
                if 0 <= ts - record[0] <= self.args.callback_window
            }
            advertisement = self.advertised_endpoints.get((src, dst, dst_port))
            if dst_port in self.args.ipp_ports or advertisement is not None:
                flow = (src, int(tcp.sport), dst, dst_port)
                if flow not in self.reported_flows:
                    self.reported_flows.add(flow)
                    if advertisement is not None and advertisement[1]:
                        self.alert(ts, "HIGH", "advertised_printer_callback", src, dst,
                                   f"TCP SYN to advertised printer {dst}:{dst_port}; connection attempt only")
                    elif dst not in self.args.trusted_printer:
                        self.alert(ts, "MEDIUM", "suspicious_ipp_connection", src, dst,
                                   f"TCP SYN to untrusted IPP-like port {dst_port}; service not verified")

        # Detect cleartext HTTP IPP requests without treating every TCP connection as IPP.
        if payload and HTTP_REQUEST_RE.match(payload) and (
            b"application/ipp" in payload[:2048].lower()
            or PRINTER_PATH_RE.match(payload)
        ):
            flow = ("ipp-request", src, int(tcp.sport), dst, int(tcp.dport))
            if flow not in self.reported_flows:
                self.reported_flows.add(flow)
                severity = "MEDIUM" if dst not in self.args.trusted_printer else "INFO"
                self.alert(ts, severity, "ipp_http_request", src, dst,
                           f"Observed printer-related HTTP/IPP payload to TCP port {tcp.dport}")

    def process(self, pkt):
        self.count += 1
        if IP in pkt:
            src, dst = pkt[IP].src, pkt[IP].dst
        elif IPv6 in pkt:
            src, dst = pkt[IPv6].src, pkt[IPv6].dst
        else:
            return
        ts = float(pkt.time)
        if UDP in pkt and int(pkt[UDP].dport) == 631:
            self.handle_browse(ts, src, dst, bytes(pkt[UDP].payload))
        if TCP in pkt:
            payload = bytes(pkt[Raw].load) if Raw in pkt else b""
            self.handle_tcp(ts, src, dst, pkt[TCP], payload)

    def export(self):
        output = self.args.output
        output.parent.mkdir(parents=True, exist_ok=True)
        if output.suffix.lower() == ".csv":
            with output.open("w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
                writer.writeheader()
                writer.writerows(self.alerts)
        else:
            output.write_text(json.dumps({
                "packets_processed": self.count,
                "alert_count": len(self.alerts),
                "alerts": self.alerts,
            }, indent=2), encoding="utf-8")
        LOGGER.info("Processed %s packets; exported %s alerts to %s",
                    self.count, len(self.alerts), output)


def main():
    args = parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    detector = Detector(args)
    try:
        if args.pcap:
            LOGGER.info("Analyzing PCAP: %s", args.pcap)
            with PcapReader(str(args.pcap)) as reader:
                for pkt in reader:
                    detector.process(pkt)
        else:
            LOGGER.info("Live monitoring started; press Ctrl+C to stop")
            # No BPF filter: also works when libpcap is not available.
            sniff(iface=args.iface, prn=detector.process, store=False)
    except KeyboardInterrupt:
        LOGGER.info("Monitoring stopped")
    finally:
        detector.export()


if __name__ == "__main__":
    main()
