#!/usr/bin/env bash
# Build ctl365 for Windows from Linux using cross-compilation
#
# Prerequisites:
#   rustup target add x86_64-pc-windows-gnu
#   sudo apt install mingw-w64 (Ubuntu/Debian)
#   sudo dnf install mingw64-gcc (Fedora)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
TARGET="x86_64-pc-windows-gnu"
OUTPUT_DIR="$PROJECT_ROOT/target/release-windows"

echo "=== Building ctl365 for Windows ==="
echo "Target: $TARGET"

# Check for required tools
if ! command -v x86_64-w64-mingw32-gcc &> /dev/null; then
    echo "Error: mingw-w64 not installed"
    echo "Install with: sudo apt install mingw-w64"
    exit 1
fi

# Add target if not present
if ! rustup target list --installed | grep -q "$TARGET"; then
    echo "Adding Rust target: $TARGET"
    rustup target add "$TARGET"
fi

# Build
echo ""
echo "Building release binary..."
cd "$PROJECT_ROOT"
cargo build --release --target "$TARGET"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Copy binary
BINARY="$PROJECT_ROOT/target/$TARGET/release/ctl365.exe"
if [[ -f "$BINARY" ]]; then
    cp "$BINARY" "$OUTPUT_DIR/"
    echo "Binary: $OUTPUT_DIR/ctl365.exe"
else
    echo "Error: Binary not found at $BINARY"
    exit 1
fi

# Copy Windows scripts
cp "$SCRIPT_DIR/install.ps1" "$OUTPUT_DIR/"
cp "$SCRIPT_DIR/uninstall.ps1" "$OUTPUT_DIR/"
cp "$SCRIPT_DIR/README.md" "$OUTPUT_DIR/"

# Create ZIP archive
VERSION=$(grep '^version' "$PROJECT_ROOT/Cargo.toml" | head -1 | cut -d'"' -f2)
ZIP_NAME="ctl365-${VERSION}-windows-x86_64.zip"

echo ""
echo "Creating release archive: $ZIP_NAME"
cd "$OUTPUT_DIR"
zip -r "../$ZIP_NAME" .

echo ""
echo "=== Build Complete ==="
echo "Archive: $PROJECT_ROOT/target/$ZIP_NAME"
echo ""
echo "Contents:"
unzip -l "$PROJECT_ROOT/target/$ZIP_NAME"
