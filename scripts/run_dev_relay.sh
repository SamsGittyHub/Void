#!/usr/bin/env bash
# Runs a development relay: void-relayd on loopback, published as a Tor onion
# service by the system tor. Its onion key and Tor state live in .dev-relay/
# (gitignored), so the address — the relay's identity, which the apps are
# built with (VOID_RELAY_ONION in ios/project.yml, RelayConfig.kt) — survives
# restarts and reboots.
#
#   scripts/run_dev_relay.sh          start it, or restart it; prints the address
#   scripts/run_dev_relay.sh stop     stop it
#   scripts/run_dev_relay.sh address  print the address
#
# This is a development relay on one machine, not a deployment: it holds what
# it holds in memory, and it is reachable only while this machine is on.
#
# Needs cargo and tor (Homebrew's is fine).
set -euo pipefail
cd "$(dirname "$0")/.."
DIR="$PWD/.dev-relay"
LOCAL="127.0.0.1:19443"

mkdir -p "$DIR/hs" "$DIR/tor"
chmod 700 "$DIR" "$DIR/hs" "$DIR/tor"

stop() {
  for name in relayd tor; do
    if [ -f "$DIR/$name.pid" ]; then
      kill "$(cat "$DIR/$name.pid")" 2>/dev/null || true
      rm -f "$DIR/$name.pid"
    fi
  done
}

case "${1:-start}" in
  stop)
    stop
    exit 0
    ;;
  address)
    cat "$DIR/hs/hostname"
    exit 0
    ;;
  start) ;;
  *)
    echo "usage: $0 [start|stop|address]" >&2
    exit 2
    ;;
esac

stop
if [ ! -x target/debug/void-relayd ]; then
  cargo build -q -p void-cli --bin void-relayd
fi

cat > "$DIR/torrc" <<EOF
SocksPort 0
DataDirectory $DIR/tor
HiddenServiceDir $DIR/hs
HiddenServicePort 9443 $LOCAL
Log notice file $DIR/tor.log
PidFile $DIR/tor.pid
RunAsDaemon 1
EOF

nohup target/debug/void-relayd --listen "$LOCAL" >"$DIR/relayd.log" 2>&1 &
echo $! > "$DIR/relayd.pid"
tor -f "$DIR/torrc" >/dev/null

for _ in $(seq 1 60); do
  [ -s "$DIR/hs/hostname" ] && break
  sleep 1
done
echo "relay: $(cat "$DIR/hs/hostname"):9443"
echo "logs:  $DIR/relayd.log, $DIR/tor.log"
