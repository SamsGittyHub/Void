//  SecuritySettingsViews.swift
//
//  The screens where PRD non-negotiable #8 applies: "No dark patterns on
//  security choices. Push, retention, and duress settings are presented
//  honestly, with the costs of each option stated."
//
//  That principle has concrete consequences, and each is marked where it shows
//  up below:
//
//  - FR-UI-06: the push on/off choice has equal visual weight. No prominent
//    "Enable" and greyed-out "Not now".
//  - FR-STOR-04: retention options are ordered shortest first, so the most
//    protective option is where the thumb lands.
//  - FR-UI-04: duress setup requires typing a confirmation phrase.
//  - Every option states its cost, not just its benefit.

import SwiftUI

// MARK: - Notifications (FR-NOTIF-04, FR-UI-06)

struct NotificationSettingsView: View {
    @Binding var pushEnabled: Bool
    @Binding var detail: NotificationDetail

    /// FR-UI-06 in one place: both options are the same control, the same size,
    /// the same colour, and each states what it costs. Neither is preselected
    /// visually — `pushEnabled` starts false per FR-NOTIF-04, but the UI does
    /// not nudge.
    var body: some View {
        Form {
            Section {
                choiceRow(
                    title: "Notifications off",
                    detail: "Messages arrive only when you open Void. Nothing tells Apple that "
                        + "your phone received anything.",
                    cost: "You will not know a message arrived until you look.",
                    selected: !pushEnabled
                ) { pushEnabled = false }

                choiceRow(
                    title: "Notifications on",
                    detail: "Void's server pings your phone when something is waiting. The ping "
                        + "carries no sender, no preview, and nothing about the message.",
                    cost: "Apple can see that your phone was pinged, and when. Over months that "
                        + "is a pattern, and it is available to anyone who can compel Apple.",
                    selected: pushEnabled
                ) { pushEnabled = true }
            } header: {
                Text("Notifications")
            } footer: {
                Text(
                    "There is no right answer here. If you are worried about a government "
                        + "asking Apple about your phone, leave this off. Otherwise, on is "
                        + "reasonable."
                )
            }

            if pushEnabled {
                Section {
                    Picker("On the lock screen", selection: $detail) {
                        // Ordered least-revealing first, same principle as
                        // retention.
                        Text("\"Message received\"").tag(NotificationDetail.generic)
                        Text("Who it's from").tag(NotificationDetail.senderName)
                        Text("A preview").tag(NotificationDetail.preview)
                    }
                    .pickerStyle(.inline)
                } header: {
                    Text("What the notification says")
                } footer: {
                    Text(
                        "Whatever you pick here is visible to anyone holding your phone, "
                            + "without unlocking it."
                    )
                }
            }
        }
        .navigationTitle("Notifications")
    }

    /// Both choices render through this, so they cannot diverge in weight.
    private func choiceRow(
        title: String,
        detail: String,
        cost: String,
        selected: Bool,
        action: @escaping () -> Void
    ) -> some View {
        Button(action: action) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: selected ? "largecircle.fill.circle" : "circle")
                    .foregroundStyle(selected ? Color.accentColor : Color.secondary)
                    .font(.title3)
                VStack(alignment: .leading, spacing: 6) {
                    Text(title).font(.headline)
                    Text(detail)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    Label(cost, systemImage: "exclamationmark.circle")
                        .font(.footnote)
                        .foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .padding(.vertical, 6)
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(selected ? [.isSelected] : [])
    }
}

enum NotificationDetail: Hashable {
    case generic, senderName, preview
}

// MARK: - Retention (FR-STOR-04)

enum RetentionPolicy: Hashable, CaseIterable {
    case oneDay, oneWeek, thirtyDays, oneYear, forever

    /// FR-STOR-04: "with the shortest options presented first". The ordering is
    /// the requirement, so it lives in the type rather than in a view that
    /// might get reordered during a redesign.
    static var ordered: [RetentionPolicy] {
        [.oneDay, .oneWeek, .thirtyDays, .oneYear, .forever]
    }

    var label: String {
        switch self {
        case .oneDay: return "24 hours"
        case .oneWeek: return "7 days"
        case .thirtyDays: return "30 days"
        case .oneYear: return "1 year"
        case .forever: return "Keep until I delete them"
        }
    }

    var consequence: String {
        switch self {
        case .forever:
            return "Messages stay on this phone until you delete them. If your phone is taken "
                + "while unlocked, everything is there."
        default:
            return "Messages are deleted from this phone automatically. Once deleted they "
                + "cannot be recovered, by you or by anyone else."
        }
    }
}

struct RetentionSettingsView: View {
    @Binding var policy: RetentionPolicy

    var body: some View {
        Form {
            Section {
                ForEach(RetentionPolicy.ordered, id: \.self) { option in
                    Button {
                        policy = option
                    } label: {
                        HStack {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(option.label).font(.headline)
                                Text(option.consequence)
                                    .font(.footnote)
                                    .foregroundStyle(.secondary)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                            Spacer()
                            if policy == option {
                                Image(systemName: "checkmark")
                                    .foregroundStyle(Color.accentColor)
                            }
                        }
                        .padding(.vertical, 4)
                    }
                    .buttonStyle(.plain)
                    .accessibilityAddTraits(policy == option ? [.isSelected] : [])
                }
            } header: {
                Text("Delete messages after")
            } footer: {
                Text(
                    "PRD §7.4.1's reasoning, in the user's words: the strongest protection "
                        + "against someone forcing you to unlock your phone is not having the "
                        + "messages on it."
                )
            }

            Section {
                Text(
                    "Shortening this applies to messages you already have. Lengthening it does "
                        + "not bring back messages that were already deleted, and does not "
                        + "extend ones that are already counting down."
                )
                .font(.footnote)
                .foregroundStyle(.secondary)
            }
        }
        .navigationTitle("Message history")
    }
}

// MARK: - Duress PIN (FR-STOR-02, FR-UI-04)

struct DuressSetupView: View {
    @State private var duressPin = ""
    @State private var confirmPhrase = ""
    @Environment(\.dismiss) private var dismiss

    var onConfirm: (String) -> Void

    private var phraseMatches: Bool {
        confirmPhrase.trimmingCharacters(in: .whitespacesAndNewlines)
            .caseInsensitiveCompare(VoidText.duressConfirmation) == .orderedSame
    }

    private var canConfirm: Bool {
        duressPin.count >= 4 && phraseMatches
    }

    var body: some View {
        Form {
            Section {
                // The disclosure PRD §7.4.1 requires "in those words or close
                // to them", fetched from the core so it is those words exactly.
                Text(VoidText.duressDisclosure)
                    .font(.callout)
                    .fixedSize(horizontal: false, vertical: true)
            } header: {
                Text("Read this first")
            }

            Section {
                Text(
                    "A duress PIN looks like a normal PIN. Entering it at the lock screen "
                        + "destroys the key that protects everything on this phone, and shows "
                        + "an empty Void as if you had just installed it."
                )
                .font(.subheadline)
                Text(
                    "It takes less than half a second and cannot be stopped once started. "
                        + "There is no way to undo it and no way for us to recover anything."
                )
                .font(.subheadline)
                .foregroundStyle(.secondary)
            } header: {
                Text("What it does")
            }

            Section {
                SecureField("Duress PIN", text: $duressPin)
                    .keyboardType(.numberPad)
                    .textContentType(.oneTimeCode)
            } header: {
                Text("Choose a duress PIN")
            } footer: {
                Text(
                    "It must be different from your normal PIN, and memorable enough to enter "
                        + "under pressure."
                )
            }

            Section {
                // FR-UI-04: "requires the user to type a confirmation phrase
                // acknowledging that destruction is irreversible and that
                // nothing is hidden." Typing, not tapping — a tap is muscle
                // memory, typing is a decision.
                Text("Type: \(VoidText.duressConfirmation)")
                    .font(.footnote.monospaced())
                    .foregroundStyle(.secondary)
                TextField("Confirmation phrase", text: $confirmPhrase)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
            } header: {
                Text("Confirm")
            }

            Section {
                Button(role: .destructive) {
                    onConfirm(duressPin)
                    dismiss()
                } label: {
                    Text("Set duress PIN").frame(maxWidth: .infinity)
                }
                .disabled(!canConfirm)
            }
        }
        .navigationTitle("Duress PIN")
        .navigationBarTitleDisplayMode(.inline)
    }
}

// MARK: - Key storage (NFR-COMP-02)

struct KeyStorageView: View {
    let backing: VaultBacking

    var body: some View {
        Form {
            Section {
                Label {
                    Text(backing.userDescription)
                        .fixedSize(horizontal: false, vertical: true)
                } icon: {
                    Image(
                        systemName: backing.isHardwareBacked
                            ? "lock.shield.fill" : "exclamationmark.shield.fill"
                    )
                    .foregroundStyle(backing.isHardwareBacked ? Color.green : Color.orange)
                }
            } header: {
                Text("How your keys are protected")
            } footer: {
                // FR-ID-02a, made user-facing. The honest claim is "not
                // extractable from a locked device", not "never in memory".
                Text(
                    "Your keys cannot be copied off a locked phone. While Void is unlocked and "
                        + "in use, they are in the phone's memory like any other app's data — "
                        + "which is why a phone taken while unlocked, or one with spyware on "
                        + "it, is outside what Void can protect."
                )
            }
        }
        .navigationTitle("Key storage")
    }
}
