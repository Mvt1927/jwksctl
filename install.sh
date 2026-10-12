#!/usr/bin/env bash
# ==============================================================================
# jwksctl Installer Script for Linux & macOS
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Mvt1927/jwksctl/main/install.sh | bash
# ==============================================================================

set -e

REPO="Mvt1927/jwksctl"
INSTALL_DIR="/usr/local/bin"
BIN_NAME="jwksctl"

echo "🔍 Detecting system architecture..."
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$OS" in
  linux)
    case "$ARCH" in
      x86_64) TARGET="jwksctl-linux-x64" ;;
      aarch64|arm64) TARGET="jwksctl-linux-arm64" ;;
      *) echo "❌ Unsupported Linux architecture: $ARCH" && exit 1 ;;
    esac
    ;;
  darwin)
    case "$ARCH" in
      x86_64) TARGET="jwksctl-darwin-x64" ;;
      arm64) TARGET="jwksctl-darwin-arm64" ;;
      *) echo "❌ Unsupported macOS architecture: $ARCH" && exit 1 ;;
    esac
    ;;
  *)
    echo "❌ Unsupported OS: $OS. Please download manual binary for Windows from GitHub Releases."
    exit 1
    ;;
esac

LATEST_RELEASE_URL="https://github.com/$REPO/releases/latest/download/$TARGET"

echo "📦 Downloading $TARGET from latest release..."
TMP_BIN="/tmp/$BIN_NAME"
curl -fL --progress-bar "$LATEST_RELEASE_URL" -o "$TMP_BIN"

chmod +x "$TMP_BIN"

echo "🚀 Installing $BIN_NAME to $INSTALL_DIR..."
if [ -w "$INSTALL_DIR" ]; then
  mv "$TMP_BIN" "$INSTALL_DIR/$BIN_NAME"
else
  echo "🔑 Need sudo permissions to move $BIN_NAME to $INSTALL_DIR:"
  sudo mv "$TMP_BIN" "$INSTALL_DIR/$BIN_NAME"
fi

echo "✅ Installed successfully!"
echo "✨ Test run: $BIN_NAME --version"
"$INSTALL_DIR/$BIN_NAME" --help | head -n 8
