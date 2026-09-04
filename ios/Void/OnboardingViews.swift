//  OnboardingViews.swift
//
//  The two screens the PRD requires before a user can do anything:
//
//  - FR-UI-05: "an in-app 'What Void does and does not protect' screen, written
//    for a non-technical reader, reachable from settings and shown once during
//    onboarding."
//  - FR-REC-01: "during onboarding the user is told, in one screen they must
//    acknowledge, that losing the device means losing all messages and their
//    identity, unless they set up a recovery method."
//
//  Both are written to be read, not dismissed. That means: no wall of text, a
//  clear split between what is protected and what is not, and no "Got it"
//  button that appears before the user has plausibly reached the bottom.

import SwiftUI

// MARK: - What Void does and does not protect (FR-UI-05)

struct ProtectionScreen: View {
    var onAcknowledge: (() -> Void)?

    /// Derived from PRD §1 and §9.3. The negative list is first and is longer,
    /// which is deliberate: a user deciding whether Void is safe enough for
    /// their situation needs the limits more than the features.
    private let protects: [(String, String)] = [
        (
            "Nobody can read your messages",
            "Not us, not the servers that carry them, not anyone watching the network. "
                + "Only the person you are talking to."
        ),
        (
            "A future quantum computer still can't",
            "Someone recording your messages today cannot decrypt them later, even with "
                + "technology that does not exist yet."
        ),
        (
            "We never learn who you talk to",
            "There is no account, no phone number, no address book on any server. "
                + "The servers that carry your messages cannot tell that two of them "
                + "belong to the same conversation."
        ),
        (
            "Your messages are deleted automatically",
            "After 30 days by default. You can make that shorter."
        ),
    ]

    private let doesNotProtect: [(String, String)] = [
        (
            "A phone someone else controls",
            "If someone installs spyware on your phone, or takes it while it is unlocked, "
                + "they can read what you can read. No messaging app can prevent that."
        ),
        (
            "The fact that you use Void",
            "Void appears on your phone like any other app. Anyone who looks can see it "
                + "is installed. In some places, that alone attracts attention."
        ),
        (
            "Notifications, if you turn them on",
            "Apple can see that your phone was pinged, and when — not by whom or about "
                + "what. Over months, that is a pattern. Notifications are off until you "
                + "turn them on."
        ),
        (
            "Someone watching both ends",
            "An adversary who can watch your internet connection and your contact's, over "
                + "a long time, may be able to tell you are talking. Void makes this "
                + "expensive. It does not make it impossible."
        ),
        (
            "Anything you tell someone else",
            "The person you message can screenshot it, repeat it, or hand over their phone."
        ),
    ]

    @State private var scrolledToEnd = false

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 28) {
                    Text("What Void protects, and what it doesn't")
                        .font(.largeTitle.bold())
                        .padding(.top, 24)

                    Text(
                        "Please read this. It is the honest version, and it is short."
                    )
                    .font(.body)
                    .foregroundStyle(.secondary)

                    section(
                        title: "What Void protects",
                        symbol: "checkmark.shield.fill",
                        tint: .green,
                        items: protects
                    )

                    section(
                        title: "What Void does not protect",
                        symbol: "exclamationmark.triangle.fill",
                        tint: .orange,
                        items: doesNotProtect
                    )

                    // A sentinel at the bottom: the acknowledge button only
                    // enables once this is on screen. Not a dark pattern in
                    // reverse — just refusing to let the safety screen be
                    // dismissed in under a second.
                    Color.clear
                        .frame(height: 1)
                        .onAppear { scrolledToEnd = true }
                }
                .padding(.horizontal, 24)
                .padding(.bottom, 32)
            }

            if onAcknowledge != nil {
                Divider()
                Button(action: { onAcknowledge?() }) {
                    Text(scrolledToEnd ? "I've read this" : "Scroll to the end")
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 14)
                }
                .buttonStyle(.borderedProminent)
                .disabled(!scrolledToEnd)
                .padding(20)
            }
        }
        // FR-UI-05 and NFR-COMP-04: this screen must be usable with VoiceOver,
        // because a user who cannot see it is exactly as entitled to the
        // warnings as one who can.
        .accessibilityElement(children: .contain)
    }

    private func section(
        title: String,
        symbol: String,
        tint: Color,
        items: [(String, String)]
    ) -> some View {
        VStack(alignment: .leading, spacing: 18) {
            Label(title, systemImage: symbol)
                .font(.title2.bold())
                .foregroundStyle(tint)

            ForEach(items, id: \.0) { item in
                VStack(alignment: .leading, spacing: 4) {
                    Text(item.0).font(.headline)
                    Text(item.1)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .accessibilityElement(children: .combine)
            }
        }
    }
}

// MARK: - Device loss (FR-REC-01)

struct DeviceLossScreen: View {
    var onSetUpRecovery: () -> Void
    var onAcceptTheRisk: () -> Void

    @State private var understood = false

    var body: some View {
        VStack(alignment: .leading, spacing: 24) {
            Spacer(minLength: 20)

            Image(systemName: "iphone.slash")
                .font(.system(size: 44))
                .foregroundStyle(.orange)

            Text("If you lose this phone")
                .font(.largeTitle.bold())

            // Straight from the core, so it cannot drift from Android's copy.
            Text(VoidText.deviceLossWarning)
                .font(.body)
                .fixedSize(horizontal: false, vertical: true)

            Text(
                "This is not a limitation we can remove. Your keys never leave this device, "
                    + "which is the reason nobody else can read your messages — and the reason "
                    + "nobody, including us, can get them back for you."
            )
            .font(.subheadline)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)

            Toggle(isOn: $understood) {
                Text("I understand that losing this phone means losing my messages and my identity.")
                    .font(.subheadline)
            }
            .padding(.top, 8)

            Spacer()

            VStack(spacing: 12) {
                Button(action: onSetUpRecovery) {
                    Text("Set up a recovery file")
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 12)
                }
                .buttonStyle(.borderedProminent)
                .disabled(!understood)

                // Both options are real choices and are presented as such.
                // Non-negotiable #8: no dark patterns on security choices. For
                // Persona A, "no recovery file" may be exactly right.
                Button(action: onAcceptTheRisk) {
                    Text("Continue without one")
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 12)
                }
                .buttonStyle(.bordered)
                .disabled(!understood)
            }
        }
        .padding(24)
    }
}

// MARK: - Onboarding flow

struct OnboardingFlow: View {
    enum Step {
        case protection
        case deviceLoss
        case done
    }

    @State private var step: Step = .protection
    var onFinished: () -> Void

    var body: some View {
        switch step {
        case .protection:
            ProtectionScreen { step = .deviceLoss }
        case .deviceLoss:
            DeviceLossScreen(
                onSetUpRecovery: { step = .done },
                onAcceptTheRisk: { step = .done }
            )
        case .done:
            Color.clear.onAppear(perform: onFinished)
        }
    }
}
