#!/bin/bash
set -e
if [[ $# -eq 1 && ("$1" == "smartdns" || "$1" == "/usr/sbin/smartdns") ]]; then
    exec "$@" -f -x -c /etc/smartdns/smartdns.conf
fi
exec "$@"
