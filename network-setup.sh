#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <agent-ipv4-address>" >&2
    exit 1
fi

route=$(ip -4 route get "$1")
iface=$(printf '%s\n' "$route" | awk '{for (i = 1; i < NF; i++) if ($i == "dev") {print $(i + 1); exit}}')
if [ -z "$iface" ]; then
    echo "No outgoing interface found for $1" >&2
    exit 1
fi

echo "Using $iface for traffic to $1"
sudo ethtool -K "$iface" tx off
ethtool -k "$iface"
