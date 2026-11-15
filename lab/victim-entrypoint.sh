#!/bin/bash
set -e

rm -f /run/dbus/pid /run/avahi-daemon/pid

/etc/init.d/dbus start
avahi-daemon --daemonize --no-chroot
cupsd

if [ "${DISABLE_CUPS_BROWSED:-0}" = "1" ]; then
    echo "[MITIGATION] cups-browsed disabled"
    exec sleep infinity
fi

echo "[VULNERABLE] Starting cups-browsed"
exec "$@"
