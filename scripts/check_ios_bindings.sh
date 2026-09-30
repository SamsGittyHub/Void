#!/usr/bin/env bash
# Checks the iOS app's Swift against the real Rust core — on Linux, without
# Apple's SDKs (D-029). What that can and cannot cover:
#
#   1. VoidCore.swift, VoidCall.swift, CoreQueue.swift and RelayConfig.swift —
#      the Swift that calls the core — type-check against the header cbindgen
#      generates from the current source, which is the header the app builds
#      against. A wrong argument type or order fails here.
#   2. The same files are compiled with tools/app-bindings/swift/BindingsCheck.swift
#      and run against libvoid_ffi.so: engines, invitations, error mapping, the
#      milliseconds guard, persistence with the right key and a wrong one.
#   3. AppState.swift and CallAudio.swift type-check against minimal stand-ins
#      for Combine and AVFoundation (tools/app-bindings/swift/stubs). That checks
#      their logic, not their use of the SDKs.
#   4. Every Swift file in the app and its tests parses.
#
# Not covered: SwiftUI, AVFoundation, Security, or anything else that needs an
# Apple SDK. CI's macOS job builds and tests the real app.
#
# Needs swiftc (set SWIFTC to use another) and cbindgen.
set -euo pipefail
cd "$(dirname "$0")/.."
REPO="$PWD"

SWIFTC="${SWIFTC:-swiftc}"
command -v "$SWIFTC" >/dev/null 2>&1 || { echo "swiftc not found; set SWIFTC" >&2; exit 1; }
command -v cbindgen >/dev/null 2>&1 || { echo "cbindgen not found: cargo install cbindgen --locked" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/ffi" "$WORK/mods" "$WORK/src"

echo "Building void-ffi and generating its header…"
cargo build -q -p void-ffi
cbindgen --quiet --crate void-ffi --config crates/void-ffi/cbindgen.toml --output "$WORK/ffi/VoidFFI.h"
printf 'module VoidFFI {\n    header "VoidFFI.h"\n    export *\n}\n' > "$WORK/ffi/module.modulemap"

# The app reaches the header through a bridging header; here it is a module.
for f in VoidCore RelayConfig CoreQueue VoidCall Models AppDirectories AppState CallAudio; do
  { echo "import VoidFFI"; cat "ios/Void/$f.swift"; } > "$WORK/src/$f.swift"
done
CORE=("$WORK/src/VoidCore.swift" "$WORK/src/RelayConfig.swift" "$WORK/src/CoreQueue.swift" "$WORK/src/VoidCall.swift")

for m in SwiftUI AVFoundation; do
  (cd "$WORK/mods" && "$SWIFTC" -emit-module -parse-as-library -swift-version 5 -module-name "$m" \
    "$REPO/tools/app-bindings/swift/stubs/$m.swift" -o "$WORK/mods/$m.swiftmodule")
done

TYPECHECK=("$SWIFTC" -typecheck -swift-version 5 -I "$WORK/ffi" -I "$WORK/mods")

echo "Type-checking the Swift that calls the core, against the generated header…"
"${TYPECHECK[@]}" "${CORE[@]}"

echo "Type-checking AppState.swift and CallAudio.swift against stand-ins…"
"${TYPECHECK[@]}" "${CORE[@]}" "$WORK/src/Models.swift" "$WORK/src/AppDirectories.swift" \
  "$WORK/src/AppState.swift" tools/app-bindings/swift/stubs/CallAudioInterface.swift
"${TYPECHECK[@]}" "${CORE[@]}" "$WORK/src/Models.swift" "$WORK/src/CallAudio.swift"

echo "Running the Swift wrapper against the real core…"
cp tools/app-bindings/swift/BindingsCheck.swift "$WORK/src/main.swift"
"$SWIFTC" -swift-version 5 -I "$WORK/ffi" "${CORE[@]}" "$WORK/src/main.swift" \
  -L target/debug -lvoid_ffi -o "$WORK/bindings-check"
LD_LIBRARY_PATH="$REPO/target/debug${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" "$WORK/bindings-check"

echo "Parsing every Swift file…"
for f in ios/Void/*.swift ios/VoidTests/*.swift ios/VoidUITests/*.swift; do
  "$SWIFTC" -parse "$f"
done

echo "  ok — the iOS app's Swift agrees with the core it calls"
