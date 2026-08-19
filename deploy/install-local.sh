#!/usr/bin/env bash
# Put `rob` on your PATH so the command works from any directory.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${1:-/usr/local/bin}"

[ -d "$TARGET" ] || { echo "No $TARGET. Try: $0 ~/.local/bin"; exit 1; }
if [ ! -w "$TARGET" ]; then
  echo "$TARGET is not writable. Either:"
  echo "  sudo $0"
  echo "  $0 ~/.local/bin      (then make sure that is on your PATH)"
  exit 1
fi

ln -sf "$REPO/bin/rob" "$TARGET/rob"
echo "Linked $TARGET/rob -> $REPO/bin/rob"
echo
echo "Now, from anywhere:"
echo "  rob serve"
echo "  rob scheduled-scan --snapshot fixtures/pdi_like_snapshot.json"
echo "  rob rules"
