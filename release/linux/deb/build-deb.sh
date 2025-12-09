#!/bin/bash
# Build .deb package for ctl365
set -euo pipefail

VERSION="${1:-0.1.0}"
ARCH="amd64"
PKG_NAME="ctl365"
PKG_DIR="${PKG_NAME}_${VERSION}_${ARCH}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$(dirname "$SCRIPT_DIR")")")"

echo "=== Building ctl365 .deb package ==="
echo "Version: $VERSION"
echo "Project: $PROJECT_ROOT"

# Build release binary
cd "$PROJECT_ROOT"
cargo build --release

# Create package structure
rm -rf "$PKG_DIR"
mkdir -p "$PKG_DIR/DEBIAN"
mkdir -p "$PKG_DIR/usr/bin"
mkdir -p "$PKG_DIR/usr/share/doc/$PKG_NAME"
mkdir -p "$PKG_DIR/usr/share/licenses/$PKG_NAME"

# Copy binary
cp target/release/ctl365 "$PKG_DIR/usr/bin/"
chmod 755 "$PKG_DIR/usr/bin/ctl365"

# Copy docs
cp README.md "$PKG_DIR/usr/share/doc/$PKG_NAME/" 2>/dev/null || true
cp COMMANDS.md "$PKG_DIR/usr/share/doc/$PKG_NAME/" 2>/dev/null || true
cp LICENSE "$PKG_DIR/usr/share/licenses/$PKG_NAME/" 2>/dev/null || true

# Create control file
cat > "$PKG_DIR/DEBIAN/control" << EOF
Package: ctl365
Version: $VERSION
Section: admin
Priority: optional
Architecture: $ARCH
Maintainer: Christopher Kelley <christopher@resolvetech.biz>
Description: Enterprise-grade Microsoft 365 deployment automation CLI
 ctl365 is a command-line tool for automating Microsoft 365 deployments,
 including security baselines, Conditional Access policies, Autopilot
 configurations, and more.
Homepage: https://github.com/resotech/ctl365
EOF

# Build package
dpkg-deb --build "$PKG_DIR"

echo ""
echo "=== Package built ==="
ls -lh "${PKG_DIR}.deb"
