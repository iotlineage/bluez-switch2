#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
bluez=$(realpath -e "$1")
out=$2
cc -g -O1 -Wall -Wextra -Werror -Wno-missing-field-initializers \
  -I"$root" -I"$bluez" $(pkg-config --cflags glib-2.0 dbus-1) \
  "$root/tests/test-live.c" "$bluez/src/bluetoothd-dbus-common.o" \
  "$bluez/gdbus/.libs/libgdbus-internal.a" "$bluez/lib/.libs/libbluetooth-internal.a" \
  -lcrypto $(pkg-config --libs glib-2.0 dbus-1) -o "$out"
