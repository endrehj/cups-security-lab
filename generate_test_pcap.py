#!/usr/bin/env python3

from scapy.all import IP, UDP, TCP, Raw, wrpcap

VICTIM = "172.20.0.4"
ATTACKER = "172.20.0.2"
PRINTER = "172.20.0.3"
PORT = 8631

packets = []
base_time = 1700000000.0

def add_packet(packet, offset):
    packet.time = base_time + offset
    packets.append(packet)

def discovery(payload, offset):
    packet = (
        IP(src=ATTACKER, dst=VICTIM)
        / UDP(sport=631, dport=631)
        / Raw(load=payload.encode())
    )
    add_packet(packet, offset)

valid_payload = (
    f'0 3 http://{PRINTER}:{PORT}/printers/LabPrinter '
    '"University Lab" "Test Printer" "Virtual Printer"\n'
)

# Test 1: Repeated discovery advertisements
for i in range(4):
    discovery(valid_payload, i)

# Test 2: Malformed discovery message
discovery("THIS IS NOT A VALID CUPS MESSAGE", 12)

# Test 3: Unexpected printer state
unexpected = (
    f'0 99 http://{PRINTER}:{PORT}/printers/LabPrinter '
    '"University Lab" "Test Printer" "Virtual Printer"\n'
)
discovery(unexpected, 13)

# Test 4: TCP connection to untrusted IPP endpoint
packet = (
    IP(src=VICTIM, dst=PRINTER)
    / TCP(sport=45000, dport=PORT, flags="S")
)
add_packet(packet, 14)

from pathlib import Path
output = Path(__file__).resolve().parent / "pcap_files/rule_tests.pcap"
output.parent.mkdir(parents=True, exist_ok=True)
wrpcap(str(output), packets)

print(f"Generated {len(packets)} test packets")
