#!/usr/bin/env bash
set -euo pipefail
IFACE="${1:-}"
[[ $EUID -eq 0 ]] || { echo "Run as root." >&2; exit 1; }
[[ -n "$IFACE" ]] || { echo "Usage: sudo $0 <interface>" >&2; exit 1; }
[[ -e "/sys/class/net/$IFACE" ]] || { echo "Unknown interface: $IFACE" >&2; exit 1; }
ip link set dev "$IFACE" xdp off
echo "XDP detached from $IFACE"
