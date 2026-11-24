//  Theme.swift
//
//  Void's look, in one place: the palette, the avatar, the badges and the
//  round buttons every screen shares.
//
//  Two rules from the PRD shape it. FR-UI-03: security state is words, never
//  only a colour or an icon someone has to learn — every badge here carries
//  its meaning as text, and colour only reinforces it. NFR-COMP-04: every
//  control has a spoken label, and nothing decorative is read aloud.

import SwiftUI

enum Theme {
    /// Void's violet: the accent on controls, links and our own messages. The
    /// asset catalog's AccentColor, so system controls and alerts match it, a
    /// shade lighter in dark mode.
    static let accent = Color("AccentColor")
    /// The deeper end of the accent, for gradients.
    static let accentDeep = Color(red: 0.29, green: 0.26, blue: 0.86)

    /// Our own message bubbles.
    static let outgoing = LinearGradient(
        colors: [Color(red: 0.49, green: 0.37, blue: 0.99), accentDeep],
        startPoint: .topLeading, endPoint: .bottomTrailing)

    /// The other person's message bubbles: the system's grouped background,
    /// so it reads in light and dark mode alike.
    static let incoming = Color(.secondarySystemBackground)

    /// Behind a call: deep space, whatever the system appearance.
    static let callBackground = LinearGradient(
        colors: [Color(red: 0.04, green: 0.04, blue: 0.10), Color(red: 0.12, green: 0.08, blue: 0.27)],
        startPoint: .top, endPoint: .bottom)

    static let verified = Color(red: 0.18, green: 0.70, blue: 0.42)
    static let warning = Color.orange
    static let danger = Color(red: 0.93, green: 0.26, blue: 0.29)
    static let answer = Color(red: 0.20, green: 0.78, blue: 0.40)

    /// Two colours for an avatar, from a contact's fingerprint: stable for the
    /// contact, different between contacts. Decoration only — never something
    /// to compare, which is what the security code is for.
    static func avatarColors(for fingerprint: Data) -> [Color] {
        let bytes = [UInt8](fingerprint.prefix(4))
        let first = bytes.count > 1 ? Double(UInt16(bytes[0]) << 8 | UInt16(bytes[1])) / 65_535 : 0.7
        let second = bytes.count > 3 ? Double(bytes[2]) / 255 : 0.2
        let hue = first
        let shifted = (hue + 0.08 + second * 0.12).truncatingRemainder(dividingBy: 1)
        return [
            Color(hue: hue, saturation: 0.55, brightness: 0.92),
            Color(hue: shifted, saturation: 0.75, brightness: 0.62),
        ]
    }
}

/// A round avatar with the contact's initials over their colours.
struct Avatar: View {
    let name: String
    let fingerprint: Data
    var size: CGFloat = 44

    private var initials: String {
        let words = name.split(separator: " ").prefix(2)
        let letters = words.compactMap { $0.first.map(String.init) }.joined()
        return letters.isEmpty ? "?" : letters.uppercased()
    }

    var body: some View {
        ZStack {
            Circle()
                .fill(
                    LinearGradient(
                        colors: Theme.avatarColors(for: fingerprint),
                        startPoint: .topLeading, endPoint: .bottomTrailing))
            Text(initials)
                .font(.system(size: size * 0.38, weight: .semibold, design: .rounded))
                .foregroundStyle(.white)
                .minimumScaleFactor(0.5)
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}

/// Security state as a word, with colour as reinforcement (FR-UI-03).
struct TrustBadge: View {
    let trust: TrustState
    var compact = true

    var body: some View {
        HStack(spacing: 4) {
            Image(systemName: icon)
                .font(.caption2.weight(.bold))
            Text(compact ? shortLabel : trust.statusLine)
                .font(.caption2.weight(.semibold))
        }
        .padding(.horizontal, 7)
        .padding(.vertical, 3)
        .background(Capsule().fill(tint.opacity(0.16)))
        .foregroundStyle(tint)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(trust.statusLine)
    }

    private var shortLabel: String {
        switch trust {
        case .verified: return "Verified"
        case .unverified: return "Not verified"
        case .keyChanged: return "Code changed"
        }
    }

    private var icon: String {
        switch trust {
        case .verified: return "checkmark.seal.fill"
        case .unverified: return "questionmark.circle"
        case .keyChanged: return "exclamationmark.triangle.fill"
        }
    }

    private var tint: Color {
        switch trust {
        case .verified: return Theme.verified
        case .unverified: return .secondary
        case .keyChanged: return Theme.warning
        }
    }
}

/// A round button for the call screens, with its label beneath.
struct CallControl: View {
    let systemImage: String
    let label: String
    var isOn = false
    var tint: Color = .white
    var diameter: CGFloat = 64
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            VStack(spacing: 8) {
                ZStack {
                    Circle()
                        .fill(isOn ? AnyShapeStyle(.white) : AnyShapeStyle(.ultraThinMaterial))
                    if tint != .white {
                        Circle().fill(tint)
                    }
                    Image(systemName: systemImage)
                        .font(.system(size: diameter * 0.36, weight: .semibold))
                        .foregroundStyle(isOn ? Color.black : Color.white)
                }
                .frame(width: diameter, height: diameter)
                Text(label)
                    .font(.caption.weight(.medium))
                    .foregroundStyle(.white.opacity(0.9))
            }
        }
        .buttonStyle(PressScaleStyle())
        .accessibilityLabel(label)
    }
}

/// Buttons that dip slightly when pressed.
struct PressScaleStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .scaleEffect(configuration.isPressed ? 0.92 : 1)
            .animation(.spring(response: 0.25, dampingFraction: 0.7), value: configuration.isPressed)
    }
}

/// A full-width prominent button in Void's colours.
struct PrimaryButtonStyle: ButtonStyle {
    var tint: Color = Theme.accent

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.headline)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 15)
            .background(
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .fill(tint.opacity(configuration.isPressed ? 0.8 : 1)))
            .foregroundStyle(.white)
            .scaleEffect(configuration.isPressed ? 0.98 : 1)
            .animation(.easeOut(duration: 0.15), value: configuration.isPressed)
    }
}

/// Soft concentric rings that pulse outwards — a call that is ringing.
struct PulsingRings: View {
    var color: Color = .white
    @State private var animate = false

    var body: some View {
        ZStack {
            ForEach(0..<3) { ring in
                Circle()
                    .stroke(color.opacity(0.35), lineWidth: 1.5)
                    .scaleEffect(animate ? 1.9 : 1)
                    .opacity(animate ? 0 : 0.9)
                    .animation(
                        .easeOut(duration: 2.4).repeatForever(autoreverses: false)
                            .delay(Double(ring) * 0.8),
                        value: animate)
            }
        }
        .onAppear { animate = true }
        .accessibilityHidden(true)
    }
}

enum Format {
    /// "14:05" today, "Yesterday", "Tue", or "12 Mar" further back.
    static func listTime(_ date: Date) -> String {
        let calendar = Calendar.current
        if calendar.isDateInToday(date) {
            return date.formatted(date: .omitted, time: .shortened)
        }
        if calendar.isDateInYesterday(date) {
            return "Yesterday"
        }
        if let days = calendar.dateComponents([.day], from: date, to: Date()).day, days < 7 {
            return date.formatted(.dateTime.weekday(.abbreviated))
        }
        return date.formatted(.dateTime.day().month(.abbreviated))
    }

    /// "Today", "Yesterday", or a date, for the separators in a conversation.
    static func dayHeading(_ date: Date) -> String {
        let calendar = Calendar.current
        if calendar.isDateInToday(date) { return "Today" }
        if calendar.isDateInYesterday(date) { return "Yesterday" }
        return date.formatted(date: .complete, time: .omitted)
    }

    /// "1:07" for a call that has run a minute and seven seconds.
    static func duration(_ seconds: TimeInterval) -> String {
        let total = max(0, Int(seconds))
        let hours = total / 3600
        let minutes = (total % 3600) / 60
        let secs = total % 60
        return hours > 0
            ? String(format: "%d:%02d:%02d", hours, minutes, secs)
            : String(format: "%d:%02d", minutes, secs)
    }
}

/// Void's mark: a dark disc in a ring of light — an eclipse.
struct VoidMark: View {
    var size: CGFloat = 80

    var body: some View {
        ZStack {
            Circle()
                .fill(
                    RadialGradient(
                        colors: [Theme.accent.opacity(0.55), .clear], center: .center,
                        startRadius: size * 0.32, endRadius: size * 0.8))
                .frame(width: size * 1.6, height: size * 1.6)
            Circle()
                .stroke(
                    AngularGradient(
                        colors: [
                            Color(red: 0.62, green: 0.52, blue: 1.0), Theme.accent,
                            Color(red: 0.36, green: 0.80, blue: 0.98), Theme.accent,
                            Color(red: 0.62, green: 0.52, blue: 1.0),
                        ], center: .center),
                    lineWidth: size * 0.075)
            Circle()
                .fill(Color.black)
                .padding(size * 0.075)
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}
