//  RelayConfig.swift
//
//  The relay this build talks to, named in exactly one place so the Tor attach
//  call and every invitation made here cannot disagree about it.

import Foundation

enum RelayConfig {
    /// The relay's onion address — its public key, so knowing it is pinning it
    /// (FR-TRANS-04). A relay for development, not a production endpoint:
    /// there is no deployed Void relay yet. `scripts/run_dev_relay.sh` runs one
    /// on a developer machine, and the build takes its address from the
    /// `VOID_RELAY_ONION` build setting (ios/project.yml) through Info.plist —
    /// configuration, not a compiled-in constant. Android's `RelayConfig`
    /// holds the same address.
    static var onionAddress: String {
        #if DEBUG
            // An end-to-end test points a debug build at the relay it started,
            // `-uiTestsRelay <onion>`, without rebuilding.
            let arguments = ProcessInfo.processInfo.arguments
            if let index = arguments.firstIndex(of: "-uiTestsRelay"), index + 1 < arguments.count {
                return arguments[index + 1]
            }
        #endif
        if let configured = Bundle.main.object(forInfoDictionaryKey: "VoidRelayOnion") as? String,
            configured.hasSuffix(".onion")
        {
            return configured
        }
        return "viptz6o5rgzml3ky6v5oddli4kchyrhkqfgqrh44b3ijikzggh4pbmid.onion"
    }

    static let port: UInt16 = 9443

    /// How an invitation names the relay it is parked on: `"<onion>:<port>"`,
    /// the same string `void_engine_attach_tor` records. Passed explicitly
    /// when making an invitation, so one can be made before Tor has connected;
    /// its upload waits in the outbox like any message.
    static var address: String { "\(onionAddress):\(port)" }
}
