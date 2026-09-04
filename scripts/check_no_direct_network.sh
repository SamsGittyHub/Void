#!/usr/bin/env bash
# FR-TRANS-03 / non-negotiable #3: "The app makes no network connection to any
# host outside Tor, with no exceptions — including for crash reporting,
# analytics, or update checks. A CI check enforces this."
#
# The core is not permitted to open sockets at all. The only crates that may
# touch the network are the relay (which is a server), the reference CLI (which
# is explicitly and loudly insecure), and the transport module (which is the
# single documented seam where the platform hands in a Tor-routed stream).
#
# Anything else that opens a socket is, by construction, a path that could carry
# traffic outside Tor — which is the exact failure this check exists to catch.
set -euo pipefail
cd "$(dirname "$0")/.."

NETWORK='TcpStream|TcpListener|UdpSocket|reqwest|hyper::|ureq|curl|URLSession|HttpURLConnection|OkHttp'

# Crates that legitimately touch sockets, and why.
ALLOWED_PATHS=(
  "crates/void-relay/"          # the relay is a server; it binds loopback only
  "crates/void-cli/"            # explicitly insecure dev tool, warns constantly
  "crates/void-client/src/transport.rs"  # the single documented Tor seam
  "crates/void-tor/"             # bootstraps Arti; the only crate that may open a
                                  # socket outside the seam above, and it only ever
                                  # opens one through a Tor circuit (D-009). Its
                                  # own dependency tree (arti-client) is where any
                                  # literal TcpStream/TcpListener use actually
                                  # lives — this crate's own source does not need
                                  # to name them.
)

FAIL=0
echo "Checking that the core cannot open a socket…"

MATCHES=$(grep -rInE "$NETWORK" --include='*.rs' --include='*.swift' --include='*.kt' \
  crates/ ios/ android/ 2>/dev/null || true)

while IFS= read -r line; do
  [ -z "$line" ] && continue
  path="${line%%:*}"
  allowed=0
  for prefix in "${ALLOWED_PATHS[@]}"; do
    case "$path" in "$prefix"*) allowed=1 ;; esac
  done
  # Comments explaining the rule are not violations of it.
  case "$line" in *"FR-TRANS-03"*|*"no network"*|*"NETWORK="*) allowed=1 ;; esac
  if [ "$allowed" -eq 0 ]; then
    echo "FAIL: $line"
    FAIL=1
  fi
done <<< "$MATCHES"

if [ "$FAIL" -eq 0 ]; then
  echo "  ok — no network access outside the documented seams"
else
  echo
  echo "A crate outside the allowed list can open a socket. Every such path is a"
  echo "path that could carry traffic outside Tor. See PRD FR-TRANS-03."
fi

echo "Checking for telemetry and crash-reporting SDKs…"
if grep -rIniE 'sentry|crashlytics|bugsnag|firebase-analytics|mixpanel|amplitude|datadog' \
    --include='*.rs' --include='*.swift' --include='*.kt' --include='*.toml' --include='*.gradle' \
    crates/ ios/ android/ 2>/dev/null | grep -viE '(check_no_direct|must not|banned|FR-TRANS-03)'; then
  echo "FAIL: a telemetry SDK appears above. FR-DIST-04 claims 'Data Not Collected'."
  FAIL=1
else
  echo "  ok — no telemetry SDKs"
fi

exit $FAIL
