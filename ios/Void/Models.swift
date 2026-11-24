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
    /// When the last message was sent or received, for sorting and the row.
    var lastActivity: Date?
}

/// One message in a conversation.
struct MessageItem: Identifiable, Equatable {
    /// Stable for the message's life: the engine's record id, or a
    /// placeholder's for a file still uploading.
    let id: String
    var text: String
    var isOutgoing: Bool
    var delivery: DeliveryState
    var timestamp: Date
    /// The file it carries, if any.
    var attachment: AttachmentInfo?
    /// A transfer in progress for that file, or one that failed.
    var transfer: TransferProgress?

    /// What the conversation list shows for this message.
    var preview: String {
        guard let attachment else { return text }
        let what: String
        if attachment.isImage {
            what = "Photo"
        } else if attachment.isVideo {
            what = "Video"
        } else {
            what = attachment.name
        }
        return text.isEmpty ? what : "\(what) · \(text)"
    }
}

/// A file moving to or from the relay.
struct TransferProgress: Equatable {
    enum Direction: Equatable {
        case upload
        case download
    }

    var direction: Direction
    /// From 0 to 1. Sealing the file counts as zero.
    var fraction: Double
    /// Why it stopped, in plain language, if it failed.
    var failure: String?
}

/// One call, as the UI needs to see it. The media secret is deliberately not
/// here: it goes straight from the engine to the media connection and is never
/// part of what a screen can render.
struct CallSession: Equatable {
    let fingerprint: Data
    var callId: Data
    let role: CallRole
    var phase: CallPhase
    /// A video call: fixed by the offer, for both ends.
    var video = false
    /// When the call connected, for the timer on the call screen.
    var connectedAt: Date?
}

/// Where a call is in its life.
enum CallPhase: Equatable {
    case publishing  // our onion service is going up
    case ringing  // offer sent, waiting for them
    case incoming  // they are calling us
    case connecting  // answered; waiting for the first authenticated audio
    case active  // audio is flowing
}
