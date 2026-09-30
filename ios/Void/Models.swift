//  Models.swift
//
//  The plain values the screens render. No SwiftUI and no FFI here: `AppState`
//  fills these from the engine, and the views only read them.

import Foundation

/// One row of the conversation list.
struct ConversationSummary: Identifiable, Equatable {
    let id: Data  // the contact fingerprint
    var name: String
    var trust: TrustState
    var lastMessage: String
    var unread: Int
}

/// One message in a conversation.
struct MessageItem: Identifiable, Equatable {
    let id: UInt64
    var text: String
    var isOutgoing: Bool
    var delivery: DeliveryState
    var timestamp: Date
}

/// One call, as the UI needs to see it. The media secret is deliberately not
/// here: it goes straight from the engine to the media connection and is never
/// part of what a screen can render.
struct CallSession: Equatable {
    let fingerprint: Data
    var callId: Data
    let role: CallRole
    var phase: CallPhase
}

/// Where a call is in its life.
enum CallPhase: Equatable {
    case publishing  // our onion service is going up
    case ringing  // offer sent, waiting for them
    case incoming  // they are calling us
    case connecting  // answered; waiting for the first authenticated audio
    case active  // audio is flowing
}
