FROM ubuntu:24.04

RUN apt-get update \
    && apt-get install -y --no-install-recommends ippsample avahi-daemon dbus tcpdump \
    && rm -rf /var/lib/apt/lists/*

COPY printer-entrypoint.sh /usr/local/bin/printer-entrypoint.sh

ENTRYPOINT ["bash", "/usr/local/bin/printer-entrypoint.sh"]
