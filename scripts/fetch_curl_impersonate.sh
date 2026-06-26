#!/usr/bin/env bash
# Fetch a prebuilt libcurl-impersonate (BoringSSL) into ./vendor.
#
# We use the actively-maintained lexiforest fork — it tracks current Chrome /
# Firefox / Safari targets (the original lwthiker/curl-impersonate is stale).
# Building BoringSSL from source is a heavy, multi-hour job; the release tarball
# ships the .so + headers prebuilt, which is all our FFI needs.
#
# Usage:  scripts/fetch_curl_impersonate.sh [version]
# Then build with the rpath already baked in (see ffi.nim passl), or export:
#   export LD_LIBRARY_PATH="$PWD/vendor/curl-impersonate/lib:$LD_LIBRARY_PATH"
set -euo pipefail

VERSION="${1:-1.0.0}"            # lexiforest/curl-impersonate release tag (no leading v in asset names varies)
REPO="lexiforest/curl-impersonate"
DEST="$(cd "$(dirname "$0")/.." && pwd)/vendor/curl-impersonate"

uname_m="$(uname -m)"
case "$uname_m" in
  x86_64)  ARCH="x86_64" ;;
  aarch64|arm64) ARCH="aarch64" ;;
  *) echo "unsupported arch: $uname_m" >&2; exit 1 ;;
esac

OS="linux-gnu"
case "$(uname -s)" in
  Darwin) OS="macos" ;;
  Linux)  OS="linux-gnu" ;;
esac

# Asset naming on the fork: libcurl-impersonate-vX.Y.Z.<arch>-<os>.tar.gz
ASSET="libcurl-impersonate-v${VERSION}.${ARCH}-${OS}.tar.gz"
URL="https://github.com/${REPO}/releases/download/v${VERSION}/${ASSET}"

echo ">> target: $DEST"
echo ">> asset : $ASSET"
echo ">> url   : $URL"
mkdir -p "$DEST/lib" "$DEST/include"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo ">> downloading…"
if ! curl -fsSL "$URL" -o "$tmp/lib.tgz"; then
  cat >&2 <<EOF

!! download failed. The asset name/version may differ for this release.
   Browse the releases page and grab the right libcurl-impersonate tarball:
     https://github.com/${REPO}/releases
   Then extract its lib/ into: $DEST/lib
EOF
  exit 1
fi

tar -xzf "$tmp/lib.tgz" -C "$tmp"
# Flatten whatever layout the tarball uses into lib/.
find "$tmp" -name 'libcurl-impersonate*.so*' -exec cp -av {} "$DEST/lib/" \;
find "$tmp" -name '*.h' -exec cp -av {} "$DEST/include/" \; 2>/dev/null || true

# Normalize a stable name our FFI looks for by default.
if [ ! -e "$DEST/lib/libcurl-impersonate.so" ]; then
  cand="$(find "$DEST/lib" -name 'libcurl-impersonate*.so*' | head -n1 || true)"
  [ -n "$cand" ] && ln -sf "$(basename "$cand")" "$DEST/lib/libcurl-impersonate.so"
fi

echo ">> installed:"
ls -la "$DEST/lib"
echo ">> done. The package rpath ($ORIGIN/../vendor/...) should pick this up,"
echo "   or: export LD_LIBRARY_PATH=\"$DEST/lib:\$LD_LIBRARY_PATH\""
