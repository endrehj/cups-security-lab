#!/bin/bash
set -euo pipefail

network="lab_lab"

network_id=$(docker network inspect --format '{{.Id}}' "$network")
subnet=$(docker network inspect \
  --format '{{(index .IPAM.Config 0).Subnet}}' "$network")
bridge="br-${network_id:0:12}"

docker run --rm --privileged --pid=host --network none \
  nicolaka/netshoot \
  nsenter -t 1 -n sh -c '
    if ! iptables -w -C DOCKER-INTERNAL \
      -i "$1" -o "$1" -s "$2" -d 224.0.0.251 \
      -p udp --dport 5353 -j ACCEPT 2>/dev/null; then

      iptables -w -I DOCKER-INTERNAL 1 \
        -i "$1" -o "$1" -s "$2" -d 224.0.0.251 \
        -p udp --dport 5353 -j ACCEPT
    fi
  ' sh "$bridge" "$subnet"

echo "Lab mDNS exception is configured."