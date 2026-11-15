# CUPS Printer Discovery and Detection Using Scapy

Educational investigation of insecure printer discovery in an isolated Docker lab.
Testing demonstrates discovery-induced network contact, not remote code execution.

## Submission layout

```text
cups_attack.py             Scapy advertisement tool
cups_detector.py           Passive live/offline detector
requirements.txt           Tested Python dependency
README.md                  Setup, experiments and results
lab/                       Compose, Dockerfiles and service/network scripts
pcap_files/historical_normal.pcap Historical normal discovery/IPP baseline
pcap_files/       Experiment captures and synthetic fixture
evidence/         19 screenshots, logs, JSON/CSV and verification
generate_test_pcap.py      Synthetic rule-validation fixture generator
tests/                     Seven detector regression tests
```

Older experiments, duplicate exports, truncated captures, their recovery files and
unused spool directories were archived outside this repository. Experiment evidence is
directly in `pcap_files/` and `evidence/`. Do not confuse historical IP assignments with
those in the experiments documented below.

## Environment and network

Host: Windows with Ubuntu 26.04 in WSL2 and Docker Desktop. The attacker and virtual
printer use Ubuntu 24.04. The victim extends `vulhub/cups-browsed:2.0.1` with Avahi
and mDNS resolution. The virtual printer runs `ippsample`'s `ippserver` on TCP 8631.

The Compose bridge `lab_lab` is internal, with no service ports published to the
host. Recorded subnet: `172.20.0.0/16`, gateway `172.20.0.1`.

| Role | Recorded IP |
| --- | --- |
| Attacker | 172.20.0.4 |
| Victim | 172.20.0.2 |
| Printer | 172.20.0.3 |

Addresses are dynamic. UDP 5353 carries mDNS discovery, UDP 631 carries legacy
browse advertisements, TCP 631 serves CUPS, and TCP 8631 serves the virtual printer.
The older `pcap_files/historical_normal.pcap` used printer IP `172.20.0.4`.

Upstream environment: [Vulhub CUPS lab](https://github.com/vulhub/vulhub/tree/master/cups-browsed/CVE-2024-47177).
The upstream folder retains the rejected CVE identifier; the assignment discusses
CVE-2024-47176, CVE-2024-47076 and CVE-2024-47175.

## Setup and explicit lab modes

Run all commands from the repository root in Ubuntu. Docker Compose is required.

```bash
# Vulnerable mode for the isolated experiments
DISABLE_CUPS_BROWSED=0 docker compose -f lab/compose.yaml up -d --build
bash lab/setup-network.sh
mkdir -p pcap_files evidence

docker compose -f lab/compose.yaml ps -a
docker compose -f lab/compose.yaml exec attacker getent hosts attacker victim printer
docker compose -f lab/compose.yaml exec victim lpstat -v
```

`setup-network.sh` enables a narrow lab-bridge UDP 5353 multicast exception in the
Docker Linux VM. It requires privileged namespace access and assumes network name
`lab_lab`. Run it after the network is recreated. It supports discovery, not mitigation.
Python and pinned Scapy are installed in the attacker image during build. The
internal running network does not provide package-repository access.

```bash
# Mitigated mode (also the default when no variable is supplied)
DISABLE_CUPS_BROWSED=1 docker compose -f lab/compose.yaml up -d --force-recreate victim
# Restore vulnerable mode for further isolated tests
DISABLE_CUPS_BROWSED=0 docker compose -f lab/compose.yaml up -d --force-recreate victim
```

Setting a variable alone does not alter an existing container; recreate it.

## Tools and example commands

`cups_attack.py` builds one legacy browse record using Scapy IP/UDP/Raw, sends it
to victim UDP 631, and observes traffic for 15 seconds. Address, port, name, state,
type, location, information and model fields are configurable. Logs and PCAPs are
exported. Default outputs are `pcap_files/cups_discovery.pcap` and
`evidence/cups_attack.log`; missing output directories are created automatically.
A callback SYN establishes an attempt, not printer registration or code execution.

```bash
docker compose -f lab/compose.yaml exec -w /workspace attacker   python3 cups_attack.py --name ExamplePrinter --port 8631   --pcap pcap_files/example_discovery.pcap   --log evidence/example_attack.log
```

Capture the printer endpoint in another terminal before sending. Stop with Ctrl+C
after the attack command completes. Use a new filename for each experiment.

```bash
docker compose -f lab/compose.yaml exec -T printer   tcpdump -i any -U -w - 'tcp port 8631' > pcap_files/example_callback.pcap
```

The attacker may not see switched victim-to-printer traffic. Separate printer-side
captures establish callbacks when attacker-side logs report none visible.

`cups_detector.py` detects untrusted browse advertisers, unexpected/malformed fields,
repeated announcements, suspicious IPP-like connection attempts and printer-related
HTTP requests. Rate defaults: 3 messages in 10 seconds, including malformed input.
Callback correlation requires the unicast advertisement recipient to connect to the
advertised endpoint within 30 seconds. Fully trusted advertiser/endpoint pairs do
not generate HIGH callback alerts. JSON/CSV include INFO observations in the total.

```bash
docker compose -f lab/compose.yaml exec -w /workspace attacker   python3 cups_detector.py --pcap pcap_files/normal.pcap   --trusted-printer 172.20.0.3 --output evidence/normal_alerts.json

docker compose -f lab/compose.yaml exec -w /workspace attacker   python3 cups_detector.py --live --iface eth0   --output evidence/live_alerts.json
```

Use capture-time addresses for offline trust lists. Stop live monitoring with Ctrl+C
to export. `historical_live_alerts.json` preserves the earlier successful live test
(5 packets, advertisement and callback alerts); its role/IP mapping differs from the experiments documented below.

## Experiments and results

Performed 15 November 2026. Primary captures: `pcap_files/`.

| Experiment | Changed fields | Printer-side result | Discovery detector result |
| --- | --- | --- | --- |
| Normal | Legitimate attribute request | 22 packets, TCP exchange | 1 INFO, no MEDIUM/HIGH |
| Unauthorized | FinalUnauthorized | 30 packets, TCP exchange | 1 HIGH |
| A | FinalVariantA, Unauthorized Office | 30 packets, TCP exchange | 1 HIGH |
| B | FinalVariantB, port 9999 | 2 packets, SYN then RST/ACK | 1 HIGH |
| C | FinalVariantC, state 99 | 30 packets, TCP exchange | 1 MEDIUM + 1 HIGH |
| Mitigation before | FinalMitigationBefore | 30 packets, TCP exchange | Advertisement sent; callback observed |
| Mitigation after | FinalMitigationAfter | 0 callback packets | 1 HIGH from 2 attacker-side packets |

Discovery destination remains UDP 631 for every variant. Port 9999 changes only
the advertised endpoint. State 99 was detected but did not prevent printer contact.
The normal `ipptool` request received a response but failed protocol validation
because of an empty `uri-security-supported` value. Treat this as legitimate
communication with a simulator validation limitation, not a passing conformance test.
The fresh normal capture contains TCP only; historical normal traffic includes
mDNS, and screenshot 02 records automatic queue discovery.

Screenshots 01-19 cover setup, baseline, detection, all three variants,
mitigation and regression tests. Corresponding logs and alert files use matching
experiment names. `capture_validation.json` records hashes and integrity checks
for the 13 experiment captures (the synthetic rule fixture is separate).

## Rule validation and regression tests

Synthetic packets validate rules without sending network traffic. Fixed 2023
timestamps and historical addresses are deliberate fixture values.

```bash
docker compose -f lab/compose.yaml exec -w /workspace attacker python3 generate_test_pcap.py
docker compose -f lab/compose.yaml exec -w /workspace attacker   python3 cups_detector.py --pcap pcap_files/rule_tests.pcap   --output evidence/rule_tests.json
docker compose -f lab/compose.yaml exec -w /workspace attacker   python3 cups_detector.py --pcap pcap_files/rule_tests.pcap   --output evidence/rule_tests.csv
docker compose -f lab/compose.yaml exec -w /workspace attacker python3 -m unittest discover -s tests -v
```

Observed: 7 synthetic packets, 11 alerts across unauthorized advertisement, repeated
discovery, malformed discovery, unexpected fields and callback categories. The
sliding-window rule crosses its threshold three times as old packets expire.
All seven regression tests passed; see `regression_tests.txt`.

## Mitigation, interpretation and limitations

Disabling `cups-browsed` removed observed printer callbacks while retaining `cupsd`.
`mitigation_service_check.txt` and screenshot 16 confirm flag 1, a running scheduler
and absence of cups-browsed. This reduces automatic discovery/queue creation.
Alternatives include vendor patches, restricting UDP 631, printer allowlists and
network segmentation; these alternatives were not experimentally tested here.

- A trust-policy warning is not proof of exploitation. The allowlisted normal test
  produced no MEDIUM/HIGH warnings; this is not a production false-positive estimate.
- Empty callback capture describes only the observation window. It is supported by
  service checks and the successful before capture, not proof of general immunity.
- Attacker-only captures omit callbacks observed at the printer. No callback alert
  from an incomplete sensor view does not imply no network contact.
- HTTP detection is packet-based: split headers, encrypted IPP and fragmentation can
  limit visibility. No full IPP parsing or TCP stream reassembly is implemented.
- Offline advertised hostnames are not resolved against current DNS; callback
  correlation uses literal IPs. Broadcast/multicast recipient correlation is absent.
- The two attacker-side packets after mitigation do not mean two advertisements or
  a successful printer callback; the attack sniffer records other relevant traffic too.

## Ethics and submission

All traffic was confined to the authorized internal Docker lab. No physical printer,
public/university system or third-party target was used. No code-execution payload
was attempted. Synthetic tests are labeled separately from captured experiments.
Submit this repository plus a separate PDF explaining the environment, implementation,
experiments, results, mitigation, limitations, references and ethical considerations.

Historical logs and screenshots retain the original paths used at capture time.
Those files now reside directly in `pcap_files/` and `evidence/`; the historical
69-packet baseline is named `pcap_files/historical_normal.pcap`, and `normal.pcap`
is the fresh 22-packet baseline. Recorded log contents were preserved.
