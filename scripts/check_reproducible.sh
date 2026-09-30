#!/usr/bin/env bash
# NFR-SEC-04: "The Rust core builds reproducibly: a documented toolchain
# produces a bit-identical artifact hash on any machine. Verified in CI on every
# release."
#
# NFR-SEC-05 then requires the hash be logged to a public transparency log.
#
# Scope, stated honestly: this covers the Rust core. It does NOT and cannot
# cover the iOS binary — the App Store re-signs and re-encrypts it, so the
# delivered artifact provably will not match a locally built one. PRD §8.1 says
# so explicitly, and claiming otherwise would be a promise broken on day one.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "Building the core twice and comparing hashes…"
export SOURCE_DATE_EPOCH=1
export CARGO_INCREMENTAL=0
export RUSTFLAGS="--remap-path-prefix=$PWD=/build"

cargo build --release -p void-crypto -p void-proto -p void-store -p void-client >/dev/null 2>&1
FIRST=$(find target/release -maxdepth 1 -name 'libvoid_*.rlib' -print0 \
  | sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1)

touch crates/void-crypto/src/lib.rs
cargo build --release -p void-crypto -p void-proto -p void-store -p void-client >/dev/null 2>&1
SECOND=$(find target/release -maxdepth 1 -name 'libvoid_*.rlib' -print0 \
  | sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1)

echo "  first:  $FIRST"
echo "  second: $SECOND"

if [ "$FIRST" != "$SECOND" ]; then
  echo "FAIL: the core did not build reproducibly."
  exit 1
fi

# The apps link the core built with the `mobile` profile (it unwinds on panic;
# see Cargo.toml), so that is the artifact that actually ships and the one
# that has to reproduce.
echo "Building the core twice with the mobile profile…"
cargo build --profile mobile -p void-crypto -p void-proto -p void-store -p void-client >/dev/null 2>&1
MOBILE_FIRST=$(find target/mobile -maxdepth 1 -name 'libvoid_*.rlib' -print0 \
  | sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1)
touch crates/void-crypto/src/lib.rs
cargo build --profile mobile -p void-crypto -p void-proto -p void-store -p void-client >/dev/null 2>&1
MOBILE_SECOND=$(find target/mobile -maxdepth 1 -name 'libvoid_*.rlib' -print0 \
  | sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1)

echo "  first:  $MOBILE_FIRST"
echo "  second: $MOBILE_SECOND"

if [ "$MOBILE_FIRST" != "$MOBILE_SECOND" ]; then
  echo "FAIL: the core did not build reproducibly with the mobile profile."
  exit 1
fi

echo "  ok — reproducible"
echo
echo "Core artifact hash (release): $FIRST"
echo "Core artifact hash (mobile):  $MOBILE_FIRST"
echo "NFR-SEC-05: this hash must be logged to the public transparency log."
echo "NOTE: this covers the Rust core only. The App Store binary is re-signed"
echo "      and re-encrypted by Apple and provably will not match. See PRD §8.1."
