#!/bin/sh
# Install the latest agevault release binary.
# Usage: curl -fsSL https://raw.githubusercontent.com/zachcheung/agevault-go/main/install.sh | sh
#   or:  curl -fsSL https://raw.githubusercontent.com/zachcheung/agevault-go/main/install.sh | INSTALL_DIR=~/.local/bin sh
set -e

REPO="zachcheung/agevault-go"
BINARY="agevault"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# Detect OS.
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$OS" in
  linux)  ;;
  darwin) ;;
  *) echo "error: unsupported OS: $OS" >&2; exit 1 ;;
esac

# Detect architecture.
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)          ARCH="amd64" ;;
  aarch64 | arm64) ARCH="arm64" ;;
  armv7l)          ARCH="armv7" ;;
  *) echo "error: unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

# Resolve latest release tag.
LATEST=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
  | grep '"tag_name"' \
  | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')

if [ -z "$LATEST" ]; then
  echo "error: could not determine latest release" >&2
  exit 1
fi

VERSION=$(echo "$LATEST" | sed 's/^v//')
URL="https://github.com/$REPO/releases/download/$LATEST/${BINARY}_${VERSION}_${OS}_$ARCH.tar.gz"

echo "Installing $BINARY $LATEST ($OS/$ARCH) to $INSTALL_DIR ..."

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

curl -fsSL "$URL" | tar -xz -C "$TMP"

# Use sudo only if the target directory is not writable.
if [ -w "$INSTALL_DIR" ]; then
  install -m 755 "$TMP/$BINARY" "$INSTALL_DIR/$BINARY"
else
  sudo install -m 755 "$TMP/$BINARY" "$INSTALL_DIR/$BINARY"
fi

echo "Done."
echo "$BINARY $("$INSTALL_DIR/$BINARY" version)"
