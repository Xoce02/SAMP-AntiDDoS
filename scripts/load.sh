#!/usr/bin/env bash
set -euo pipefail

IFACE="${1:-}"
PORT="${2:-7777}"
MODE="${3:-drv}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OBJ="$ROOT_DIR/build/xdp_samp.o"

usage() {
  echo "Usage: sudo $0 <interface> [port] [drv|generic]"
  echo "Example: sudo $0 eth0 7777 drv"
}

[[ $EUID -eq 0 ]] || { echo "Run as root." >&2; exit 1; }
[[ -n "$IFACE" ]] || { usage; exit 1; }
[[ "$PORT" =~ ^[0-9]+$ ]] && (( PORT >= 1 && PORT <= 65535 )) || {
  echo "Invalid UDP port: $PORT" >&2; exit 1;
}
[[ "$MODE" == "drv" || "$MODE" == "generic" ]] || { usage; exit 1; }

for cmd in clang ip; do
  command -v "$cmd" >/dev/null || { echo "Missing dependency: $cmd" >&2; exit 1; }
done

[[ -e "/sys/class/net/$IFACE" ]] || {
  echo "Unknown interface: $IFACE" >&2
  echo "Run: ip -br link" >&2
  exit 1
}

if ip -details link show dev "$IFACE" | grep -qE 'prog/xdp|xdp id'; then
  if [[ "${FORCE:-0}" != "1" ]]; then
    echo "An XDP program is already attached to $IFACE." >&2
    echo "Refusing to replace it. Use FORCE=1 only if you know what you are replacing." >&2
    exit 1
  fi
  ip link set dev "$IFACE" xdp off || true
fi

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64) TARGET_ARCH=x86 ;;
  aarch64|arm64) TARGET_ARCH=arm64 ;;
  *) echo "Unsupported architecture for this helper: $ARCH" >&2; exit 1 ;;
esac

ARCH_INC="/usr/include/${ARCH}-linux-gnu"
mkdir -p "$ROOT_DIR/build"

clang -O2 -g -target bpf \
  -D__TARGET_ARCH_${TARGET_ARCH} \
  -Dgameport="$PORT" \
  -I"$ARCH_INC" \
  -c "$ROOT_DIR/xdp_samp.c" \
  -o "$OBJ"

if [[ "$MODE" == "drv" ]]; then
  ip link set dev "$IFACE" xdpdrv obj "$OBJ" sec xdp
else
  ip link set dev "$IFACE" xdpgeneric obj "$OBJ" sec xdp
fi

echo "SA-MP XDP Lite attached: interface=$IFACE UDP/$PORT mode=$MODE"
ip -details link show dev "$IFACE" | sed -n '1,8p'
