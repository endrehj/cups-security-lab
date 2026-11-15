FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-venv tcpdump iproute2 iputils-ping curl \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir scapy==2.8.0

ENV PATH="/opt/venv/bin:${PATH}"
WORKDIR /workspace

CMD ["sleep", "infinity"]