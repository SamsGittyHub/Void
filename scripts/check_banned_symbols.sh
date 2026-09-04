#!/usr/bin/env bash
# FR-TRANS-02 / non-negotiable #4: "WebRTC, ICE, STUN, and TURN are banned from
# the codebase. Enforced by CI."
#
# The PRD says "a CI check fails the build if any of these symbols appear in the
# dependency graph". This checks both: the source tree, and the resolved
# dependency list.
#
# Why this is a build failure and not a lint: these protocols leak the real IP
# address by design. There is no configuration of WebRTC that is safe here, so
# there is no version of this that should be a warning someone can dismiss.
set -euo pipefail
cd "$(dirname "$0")/.."

BANNED='webrtc|libwebrtc|\bICE\b|ice_candidate|IceCandidate|\bSTUN\b|stun_|StunClient|\bTURN\b|turn_server|TurnClient|RTCPeerConnection'
FAIL=0

echo "Checking source tree for banned real-time-media symbols…"
if grep -rInE "$BANNED" \
    --include='*.rs' --include='*.swift' --include='*.kt' --include='*.toml' \
    crates/ ios/ android/ 2>/dev/null \
    | grep -viE '(banned|prohibited|forbid|check_banned|must not|FR-TRANS-02|non-negotiable)' ; then
  echo "FAIL: a banned symbol appears above."
  echo "      WebRTC/ICE/STUN/TURN leak the real IP address. See PRD FR-TRANS-02."
  FAIL=1
else
  echo "  ok — no banned symbols in source"
fi

echo "Checking the resolved dependency graph…"
if [ -f Cargo.lock ]; then
  if grep -InE '^name = "(webrtc|str0m|stun|turn|libnice)' Cargo.lock ; then
    echo "FAIL: a banned crate is in the dependency graph."
    FAIL=1
  else
    echo "  ok — no banned crates resolved"
  fi
else
  echo "  (no Cargo.lock yet; run 'cargo generate-lockfile')"
fi

exit $FAIL
