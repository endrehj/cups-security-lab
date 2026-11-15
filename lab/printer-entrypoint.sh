#!/bin/bash
set -e

rm -f /run/dbus/pid /run/avahi-daemon/pid
mkdir -p /run/dbus /spool

dbus-daemon --system
avahi-daemon --daemonize --no-chroot

exec ippserver -v -n printer -p 8631 -d /spool "Lab Printer"