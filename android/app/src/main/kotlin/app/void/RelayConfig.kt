package app.void

/**
 * The relay this build talks to, named in exactly one place so the Tor attach
 * call and every invitation made here cannot disagree about it.
 *
 * A relay for development, not a production endpoint — there is no deployed
 * Void relay yet. It runs as `void-relayd` on a developer machine, reachable
 * only through this onion address, and goes away when that process stops. A
 * release needs this to come from configuration, not a compiled-in constant.
 * iOS's `RelayConfig` holds the same values.
 */
object RelayConfig {
    const val ONION_ADDRESS = "hxxfawyq3xymghgqkalw4ut6emtt5nhaimquyrvi7ngyeecrri4qy5qd.onion"
    const val PORT = 9443

    /**
     * How an invitation names the relay it is parked on — the same string
     * `void_engine_attach_tor` records. Passed explicitly when making an
     * invitation, so one can be made before Tor has connected.
     */
    const val ADDRESS = "$ONION_ADDRESS:$PORT"
}
