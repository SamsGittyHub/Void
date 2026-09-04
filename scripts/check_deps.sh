#!/usr/bin/env bash
# NFR-SEC-07: "every third-party crate in the trusted path is pinned, vendored,
# reviewed on update … Adding a dependency to the crypto or transport path
# requires a written justification in the PR."
#
# void-crypto used to have zero third-party dependencies, and that emptiness
# was worth defending mechanically. D-006's migration is the one deliberate,
# narrow exception: `ml-kem` and `ml-dsa` (RustCrypto, ACVP-track
# implementations of FIPS 203 / FIPS 204) replaced the clean-room PQC code
# that could never be validated in this build environment. This check now
# allows exactly those two names, exactly-version-pinned (`version = "=x.y.z"`,
# not a range — a range would let a routine `cargo update` silently swap in
# unreviewed code in the crypto path), and fails on anything else, including
# a third dependency added without the same review this pair got.
set -euo pipefail
cd "$(dirname "$0")/.."

ALLOWED_CRYPTO_DEPS='^(ml-kem|ml-dsa)$'

FAIL=0
echo "Checking void-crypto's dependency table against the D-006 allow-list…"
DEP_LINES=$(awk '/^\[dependencies\]/{f=1;next} /^\[/{f=0} f && NF && $0 !~ /^#/' \
  crates/void-crypto/Cargo.toml || true)
if [ -z "$DEP_LINES" ]; then
  echo "FAIL: void-crypto's dependency table is empty — expected ml-kem and ml-dsa."
  echo "      If D-006's migration was reverted, update this check and its comment too."
  FAIL=1
else
  SEEN=""
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    name=$(echo "$line" | sed -E 's/^"?([A-Za-z0-9_-]+)"?[[:space:]]*=.*/\1/')
    if ! echo "$name" | grep -qE "$ALLOWED_CRYPTO_DEPS"; then
      echo "FAIL: void-crypto gained an unreviewed dependency: $name"
      echo "      Only ml-kem and ml-dsa are allowed here (D-006). A new one needs the"
      echo "      same written justification (NFR-SEC-07) and an update to this check."
      FAIL=1
      continue
    fi
    if ! echo "$line" | grep -qE 'version[[:space:]]*=[[:space:]]*"='; then
      echo "FAIL: $name is not exact-version-pinned (expected version = \"=x.y.z\")."
      echo "      A range would let 'cargo update' swap in unreviewed code silently."
      FAIL=1
    fi
    SEEN="$SEEN $name"
  done <<< "$DEP_LINES"
  for want in ml-kem ml-dsa; do
    case " $SEEN " in
      *" $want "*) ;;
      *)
        echo "FAIL: expected dependency '$want' is missing from void-crypto."
        FAIL=1
        ;;
    esac
  done
  [ "$FAIL" -eq 0 ] && echo "  ok — void-crypto depends on exactly ml-kem and ml-dsa, both pinned"
fi

echo "Checking that only void-ffi permits unsafe code…"
# Match the actual crate attribute, not prose about it: an earlier version of
# this check failed on void-ffi's own module documentation, which explains that
# it is the one crate lacking the attribute.
has_forbid() {
  grep -qE '^\s*#!\[forbid\(unsafe_code\)\]' "$1"
}
# void-ffi is the C ABI iOS calls; void-jni is the JNI ABI Android calls
# (D-023). Two boundaries, not one, because C-pointer unsafety and
# JNIEnv/jobject unsafety are different shapes — see void-jni's module docs.
# Neither wraps the other's ABI; both depend only on the safe core crates.
FFI_BOUNDARY_CRATES='^(void-ffi|void-jni)$'
for manifest in crates/*/Cargo.toml; do
  crate=$(basename "$(dirname "$manifest")")
  lib="crates/$crate/src/lib.rs"
  [ -f "$lib" ] || continue
  if echo "$crate" | grep -qE "$FFI_BOUNDARY_CRATES"; then
    if has_forbid "$lib"; then
      echo "FAIL: $crate forbids unsafe, but it is an FFI boundary."
      FAIL=1
    fi
    continue
  fi
  if ! has_forbid "$lib"; then
    echo "FAIL: $crate does not have #![forbid(unsafe_code)] (NFR-SEC-02)."
    FAIL=1
  fi
done
[ "$FAIL" -eq 0 ] && echo "  ok — unsafe is confined to void-ffi and void-jni"

exit $FAIL
