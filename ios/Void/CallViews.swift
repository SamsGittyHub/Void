//  CallViews.swift
//
//  The call screen, the incoming-call sheet, and the disclosure a user has to
//  read before their first call.
//
//  FR-UI-03 wants security state in plain language rather than iconography
//  someone has to learn. Two things follow from that here.
//
//  **The delay is stated, not hidden.** A call over Tor runs about
//  three-quarters of a second each way (measured — see
//  experiments/onion-call/RESULTS.md). The mic is open both ways, so this is a
//  call; it is a call with noticeable lag, and a user who is told that adapts
//  while a user who is not assumes the app is broken.
//
//  **The disclosure text comes from the core.** `CALL_DISCLOSURE` lives in
//  `void_proto::call` next to the behaviour it describes, so this file cannot
//  soften it and the Kotlin one cannot drift from it. It says what a call
//  actually costs — that the other person learns you are online, and that a
//  call's traffic shape is nothing like messaging's — and it does not claim
//  location exposure, because media runs over onion services in both
//  directions and that claim would be false.

import SwiftUI

// MARK: - The active call screen

struct CallView: View {
    let contactName: String
    let phase: CallPhase
    @Binding var isMuted: Bool
    var onHangUp: () -> Void

    var body: some View {
        VStack(spacing: 28) {
            Spacer()

            VStack(spacing: 8) {
                Text(contactName)
                    .font(.title2.weight(.semibold))
                Text(statusLine)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }

            if phase == .active {
                muteButton
                // Not an apology — an instruction. Users who know about the
                // lag pause for it; users who do not talk over each other and
                // conclude the app is broken.
                Text("About a second of delay each way — leave a beat before you reply.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
                    .accessibilityIdentifier("callLatencyExplanation")
            }

            Spacer()

            Button(role: .destructive, action: onHangUp) {
                Text(phase == .active ? "End" : "Cancel")
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 14)
            }
            .buttonStyle(.borderedProminent)
            .padding(.horizontal, 32)
            .accessibilityIdentifier("endCallButton")
        }
        .padding(.bottom, 32)
    }

    /// Mute, not push-to-talk: the microphone is open both ways for the whole
    /// call. Muting stops the microphone, not the emission — silence frames go
    /// out on the same cadence, so the traffic shape of a muted call and a
    /// talking one are identical.
    private var muteButton: some View {
        Button {
            isMuted.toggle()
        } label: {
            Circle()
                .fill(isMuted ? Color.secondary.opacity(0.25) : Color.accentColor)
                .frame(width: 160, height: 160)
                .overlay(
                    VStack(spacing: 6) {
                        Image(systemName: isMuted ? "mic.slash.fill" : "mic.fill")
                            .font(.system(size: 44))
                        Text(isMuted ? "Muted" : "Mute")
                            .font(.callout.weight(.medium))
                    }
                    .foregroundStyle(isMuted ? Color.primary : Color.white)
                )
        }
        .buttonStyle(.plain)
        .accessibilityIdentifier("muteButton")
        .accessibilityLabel(isMuted ? "Unmute" : "Mute")
    }

    private var statusLine: String {
        switch phase {
        case .publishing:
            return "Setting up a private connection…"
        case .ringing:
            // Honest about the wait: the offer travels through their mailbox,
            // and that takes up to a minute (D-028).
            return "Ringing. It can take up to a minute to reach them."
        case .incoming:
            return "Incoming"
        case .connecting:
            return "Connecting…"
        case .active:
            return "Connected over Tor"
        }
    }
}

// MARK: - The incoming call sheet

struct IncomingCallView: View {
    let contactName: String
    let isVerified: Bool
    var onAnswer: () -> Void
    var onDecline: () -> Void

    var body: some View {
        VStack(spacing: 24) {
            Spacer()

            VStack(spacing: 10) {
                Text(contactName)
                    .font(.title.weight(.semibold))
                Text("wants to talk")
                    .foregroundStyle(.secondary)

                // FR-UI-03: the trust state is a sentence, not a badge. An
                // unverified contact on a call is worth saying out loud,
                // because voice feels like proof of identity and is not.
                Text(
                    isVerified
                        ? "You've checked their security code."
                        : "You haven't checked their security code yet. A voice can be imitated."
                )
                .font(.footnote)
                .foregroundStyle(isVerified ? .secondary : .primary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 32)
                .accessibilityIdentifier("incomingCallTrustNote")
            }

            Spacer()

            HStack(spacing: 20) {
                Button(role: .destructive, action: onDecline) {
                    Text("Decline")
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 14)
                }
                .buttonStyle(.bordered)
                .accessibilityIdentifier("declineCallButton")

                Button(action: onAnswer) {
                    Text("Answer")
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 14)
                }
                .buttonStyle(.borderedProminent)
                .accessibilityIdentifier("answerCallButton")
            }
            .padding(.horizontal, 24)
        }
        .padding(.bottom, 32)
    }
}

// MARK: - The disclosure

/// Shown before a call connects — placing one or answering one.
///
/// The body text is `void_proto::call::CALL_DISCLOSURE`, fetched rather than
/// retyped so it cannot be softened here. Per non-negotiable #8 the option
/// states its cost, and per FR-UI-03 it does so in sentences rather than a
/// warning triangle nobody reads.
///
/// The confirming button is not "OK". A user who has read this is agreeing to
/// something specific, so the button says what they are agreeing to.
struct CallDisclosureView: View {
    let contactName: String
    let isAnswering: Bool
    var onContinue: () -> Void
    var onCancel: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            Text(isAnswering ? "Before you answer" : "Before you call")
                .font(.title2.weight(.semibold))

            ScrollView {
                Text(VoidCore.callDisclosure)
                    .font(.body)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("callDisclosureText")
            }

            Text(
                isAnswering
                    ? "Answering tells \(contactName) you're here."
                    : "Calling tells \(contactName) you're here."
            )
            .font(.footnote)
            .foregroundStyle(.secondary)

            HStack(spacing: 16) {
                Button(action: onCancel) {
                    Text("Not now")
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 14)
                }
                .buttonStyle(.bordered)
                .accessibilityIdentifier("callDisclosureCancel")

                Button(action: onContinue) {
                    Text(isAnswering ? "Answer anyway" : "Call anyway")
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 14)
                }
                .buttonStyle(.borderedProminent)
                .accessibilityIdentifier("callDisclosureContinue")
            }
        }
        .padding(24)
    }
}

#Preview("Active call") {
    CallView(
        contactName: "Bob",
        phase: .active,
        isMuted: .constant(false),
        onHangUp: {}
    )
}

#Preview("Incoming") {
    IncomingCallView(contactName: "Bob", isVerified: false, onAnswer: {}, onDecline: {})
}

#Preview("Disclosure") {
    CallDisclosureView(contactName: "Bob", isAnswering: false, onContinue: {}, onCancel: {})
}
