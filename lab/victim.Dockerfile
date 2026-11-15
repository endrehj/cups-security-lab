FROM vulhub/cups-browsed:2.0.1

RUN apt-get update \
    && apt-get install -y --no-install-recommends avahi-daemon libnss-mdns \
    && rm -rf /var/lib/apt/lists/*

COPY victim-entrypoint.sh /usr/local/bin/victim-entrypoint.sh

ENTRYPOINT ["bash", "/usr/local/bin/victim-entrypoint.sh"]
CMD ["cups-browsed", "--debug"]