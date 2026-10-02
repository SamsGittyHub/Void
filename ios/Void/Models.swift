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
    /// The store record behind it, for fetching a file's bytes. Zero for a
    /// message shown before the engine has stored it.
    var recordId: UInt64 = 0
    var text: String
    var isOutgoing: Bool
    var delivery: DeliveryState
    var timestamp: Date
    /// The file this message is, if it is one. Its bytes are fetched when it
    /// is on screen (`AppState.attachmentData`), never carried here.
    var attachment: AttachmentInfo? = nil
    /// Records of it still waiting to leave; zero once sent, and for anything
    /// received. One leaves per `VoidCore.padIntervalMs`.
    var fragmentsRemaining: Int = 0
}

/// What a file in a conversation is, without its bytes.
struct AttachmentInfo: Equatable {
    let name: String
    let mime: String
    /// Size in bytes.
    let size: Int

    /// Whether to show it as a picture rather than a file card.
    var isImage: Bool { mime.lowercased().hasPrefix("image/") }

    /// What the conversation list shows for it.
    var summary: String {
        if isImage { return "Photo" }
        return name.isEmpty ? "File" : name
    }
}

/// A file the user picked and has not sent yet.
struct PendingAttachment: Equatable {
    let name: String
    let mime: String
    let data: Data
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
