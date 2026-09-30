#!/usr/bin/env bash
# Builds void-ffi for iOS device and simulator, generates its C header, and
# packages both into an XCFramework the Xcode project links against.
#
# This is the concrete implementation of the build prompt's "build the Rust
# core as a static library for arm64 device and simulator; XCFramework" and
# "generate a C header for void-ffi (cbindgen) and a bridging header".
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v cbindgen >/dev/null 2>&1; then
  echo "cbindgen not found. Install it with: cargo install cbindgen" >&2
  exit 1
fi

echo "Building void-ffi for iOS device and simulator…"
TARGETS=(aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios)
for t in "${TARGETS[@]}"; do
  rustup target add "$t" >/dev/null 2>&1 || true
  # `mobile`, not `release`: it unwinds on panic, so void-ffi's catch_unwind
  # guards turn a core panic into an error code (Cargo.toml has the why).
  cargo build -p void-ffi --profile mobile --target "$t"
done

echo "Generating VoidFFI.h…"
HEADER_DIR=ios/generated/include
rm -rf "$HEADER_DIR"
mkdir -p "$HEADER_DIR"
cbindgen --crate void-ffi --config crates/void-ffi/cbindgen.toml --output "$HEADER_DIR/VoidFFI.h"

echo "Building the simulator fat library (arm64 + x86_64)…"
SIM_LIB_DIR=target/ios-sim-universal
mkdir -p "$SIM_LIB_DIR"
lipo -create \
  "target/aarch64-apple-ios-sim/mobile/libvoid_ffi.a" \
  "target/x86_64-apple-ios/mobile/libvoid_ffi.a" \
  -output "$SIM_LIB_DIR/libvoid_ffi.a"

echo "Packaging Void.xcframework…"
rm -rf ios/VoidFFI.xcframework
xcodebuild -create-xcframework \
  -library "target/aarch64-apple-ios/mobile/libvoid_ffi.a" -headers "$HEADER_DIR" \
  -library "$SIM_LIB_DIR/libvoid_ffi.a" -headers "$HEADER_DIR" \
  -output ios/VoidFFI.xcframework

echo "Done: ios/VoidFFI.xcframework"
