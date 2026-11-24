#!/usr/bin/env bash
# Runs the two-phone end-to-end test, ios/VoidUITests/EndToEndUITests.swift:
# two Simulators, the development relay behind a Tor onion service, and the
# live Tor network. One Simulator plays Ada, who makes an invitation; the
# other plays Bea, who accepts it. Then messages both ways, a photo, a voice
# call and a video call, all driven through the real interface.
#
#   scripts/run_ios_e2e.sh             build for testing, then run
#   scripts/run_ios_e2e.sh --no-build  run the last build again
#
# Each run starts both sides from new identities, and leaves what it saw in
# .e2e/<run>/ (gitignored): each side's log, its screenshots, and the
# xcodebuild output and result bundle.
#
# Expect 15–30 minutes. Tor sets the pace, not the app: connecting, parking
# an invitation, and dialling a call's onion service each take a while.
#
# Needs: ios/VoidFFI.xcframework (scripts/build_ios.sh), xcodegen, and what
# scripts/run_dev_relay.sh needs (cargo, tor). The Simulators are the ones
# named Void-Call-A and Void-Call-B, made if missing; set VOID_E2E_SIM_A and
# VOID_E2E_SIM_B to UDIDs to use others.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"

BUILD=1
case "${1:-}" in
  --no-build) BUILD=0 ;;
  "") ;;
  *)
    echo "usage: $0 [--no-build]" >&2
    exit 2
    ;;
esac

# The relay: the development one, started if it is not already running.
running() { [ -f ".dev-relay/$1.pid" ] && kill -0 "$(cat ".dev-relay/$1.pid")" 2>/dev/null; }
if ! running relayd || ! running tor; then
  scripts/run_dev_relay.sh
fi
RELAY="$(scripts/run_dev_relay.sh address)"

# The two Simulators.
simulator() {
  local name="$1" id
  id="$(xcrun simctl list devices | grep -E "^ +$name \(" | head -1 | sed -E 's/.*\(([0-9A-F-]{36})\).*/\1/')"
  if [ -z "$id" ]; then
    local runtime type
    runtime="$(xcrun simctl list runtimes | awk '/^iOS/ { id = $NF } END { print id }')"
    type="$(xcrun simctl list devicetypes | awk -F'[()]' '/^iPhone [0-9]+ \(/ { id = $2 } END { print id }')"
    id="$(xcrun simctl create "$name" "$type" "$runtime")"
  fi
  echo "$id"
}
SIM_A="${VOID_E2E_SIM_A:-$(simulator Void-Call-A)}"
SIM_B="${VOID_E2E_SIM_B:-$(simulator Void-Call-B)}"
for id in "$SIM_A" "$SIM_B"; do
  xcrun simctl bootstatus "$id" -b >/dev/null
done

PRODUCTS="$ROOT/ios/DerivedData/Build/Products"
if [ "$BUILD" = 1 ]; then
  (cd ios && xcodegen generate >/dev/null)
  echo "Building for testing…"
  xcodebuild build-for-testing -project ios/Void.xcodeproj -scheme Void \
    -destination "id=$SIM_A" -derivedDataPath ios/DerivedData -quiet
fi
XCTESTRUN="$(ls -t "$PRODUCTS"/*iphonesimulator*.xctestrun 2>/dev/null | head -1)"
if [ -z "$XCTESTRUN" ]; then
  echo "No test build in ios/DerivedData: run without --no-build first." >&2
  exit 1
fi

# The microphone, granted ahead: a permission alert over a ringing call is
# not what this test is about. (The Simulator has no camera; the app sends a
# test pattern there, so there is nothing to grant for it.)
for id in "$SIM_A" "$SIM_B"; do
  xcrun simctl install "$id" "$PRODUCTS/Debug-iphonesimulator/Void.app"
  xcrun simctl privacy "$id" grant microphone app.void.Void
done

RUN="e2e$(date +%Y%m%d%H%M%S)"
OUT="$ROOT/.e2e/$RUN"
mkdir -p "$OUT"
echo "Run $RUN against $RELAY:9443"
echo "Watch it: tail -f $OUT/log-ada.txt $OUT/log-bea.txt"

side() {
  local name="$1" id="$2" test="$3"
  TEST_RUNNER_E2E_DIR="$OUT" TEST_RUNNER_E2E_RELAY="$RELAY" TEST_RUNNER_E2E_RUN="$RUN" \
    xcodebuild test-without-building -xctestrun "$XCTESTRUN" -destination "id=$id" \
    -only-testing:"VoidUITests/EndToEndUITests/$test" \
    -resultBundlePath "$OUT/$name.xcresult" >"$OUT/$name-xcodebuild.log" 2>&1
}
side ada "$SIM_A" testAda &
ADA=$!
side bea "$SIM_B" testBea &
BEA=$!
wait "$ADA" && ADA_STATUS=0 || ADA_STATUS=$?
wait "$BEA" && BEA_STATUS=0 || BEA_STATUS=$?
# A test that skips passes as far as xcodebuild is concerned — and these skip
# when the environment above never reached them. Here, that is a failure.
grep -q "Test Case .* skipped" "$OUT/ada-xcodebuild.log" && ADA_STATUS=skipped
grep -q "Test Case .* skipped" "$OUT/bea-xcodebuild.log" && BEA_STATUS=skipped

for name in ada bea; do
  echo
  echo "── $name"
  cat "$OUT/log-$name.txt" 2>/dev/null || echo "(no log)"
  grep -E "error:|failed|Test Case .* (passed|failed|skipped)" "$OUT/$name-xcodebuild.log" | head -10 || true
done
echo
echo "Screenshots and results: $OUT"
if [ "$ADA_STATUS" = 0 ] && [ "$BEA_STATUS" = 0 ]; then
  echo "PASSED"
else
  echo "FAILED (Ada: $ADA_STATUS, Bea: $BEA_STATUS)"
  exit 1
fi
