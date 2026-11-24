//  CallViews.swift
//
//  The call screen, voice and video; the incoming-call screen; and the
//  disclosure a user reads before every call.
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
//  **The disclosure text comes from the core.** `CALL_DISCLOSURE` and, for a
//  video call, `VIDEO_CALL_DISCLOSURE` live in `void_proto::call` next to the
//  behaviour they describe, so this file cannot soften them and the Kotlin one
//  cannot drift from them. They say what a call actually costs — that the
//  other person learns you are online, and that a call's traffic shape is
//  nothing like messaging's — and they do not claim location exposure, because
//  media runs over onion services in both directions and that would be false.

import SwiftUI

// MARK: - The call screen

struct CallView: View {
    @EnvironmentObject var state: AppState
    let call: CallSession
    let contactName: String
    @Binding var isMuted: Bool
    var onHangUp: () -> Void

    @State private var showingDetails = false
    @State private var localCorner: Alignment = .topTrailing

    private var showsVideo: Bool {
        call.video && call.phase == .active && state.callVideo != nil
    }

    var body: some View {
        ZStack {
            Theme.callBackground.ignoresSafeArea()
            if showsVideo, let video = state.callVideo {
                RemoteVideoView(video: video, quarterTurns: state.remoteRotation)
                    .ignoresSafeArea()
                    .opacity(state.remoteVideo.started && !state.remoteVideo.cameraOff ? 1 : 0)
                    .animation(.easeInOut(duration: 0.3), value: state.remoteVideo)
                    .accessibilityLabel("\(contactName)'s camera")
                    .accessibilityIdentifier("remoteVideo")
                if !state.remoteVideo.started || state.remoteVideo.cameraOff {
                    portrait(subtitle: state.remoteVideo.cameraOff ? "Camera off" : "Waiting for their picture…")
                }
                LinearGradient(colors: [.black.opacity(0.55), .clear], startPoint: .top, endPoint: .center)
                    .ignoresSafeArea()
                    .allowsHitTesting(false)
                LinearGradient(colors: [.clear, .black.opacity(0.6)], startPoint: .center, endPoint: .bottom)
                    .ignoresSafeArea()
                    .allowsHitTesting(false)
            } else {
                portrait(subtitle: statusLine)
            }

            VStack(spacing: 0) {
                topBar
                Spacer()
                if call.phase == .active {
                    // Not an apology — an instruction. Users who know about the
                    // lag pause for it; users who do not talk over each other
                    // and conclude the app is broken.
                    Text("About a second of delay each way — leave a beat before you reply.")
                        .font(.footnote)
                        .foregroundStyle(.white.opacity(0.75))
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 32)
                        .padding(.bottom, 18)
                        .accessibilityIdentifier("callLatencyExplanation")
                }
                controls
            }

            if showsVideo, let video = state.callVideo {
                LocalVideoView(video: video)
                    .frame(width: 112, height: 150)
                    .clipShape(RoundedRectangle(cornerRadius: 18, style: .continuous))
                    .overlay(
                        RoundedRectangle(cornerRadius: 18, style: .continuous)
                            .stroke(.white.opacity(0.25), lineWidth: 1))
                    .overlay {
                        if !state.isCameraOn {
                            ZStack {
                                RoundedRectangle(cornerRadius: 18).fill(.black.opacity(0.75))
                                Image(systemName: "video.slash.fill").foregroundStyle(.white)
                            }
                        }
                    }
                    .shadow(color: .black.opacity(0.4), radius: 12, y: 6)
                    .padding(.top, 70)
                    .padding(.horizontal, 16)
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: localCorner)
                    .gesture(
                        DragGesture(minimumDistance: 20).onEnded { drag in
                            withAnimation(.spring(response: 0.4, dampingFraction: 0.8)) {
                                localCorner = drag.translation.width < 0 ? .topLeading : .topTrailing
                            }
                        }
                    )
                    .accessibilityLabel(state.isCameraOn ? "Your camera" : "Your camera is off")
                    .accessibilityIdentifier("localVideo")
            }
        }
        .preferredColorScheme(.dark)
        .sheet(isPresented: $showingDetails) {
            CallDetails(call: call, stats: state.callStats, video: state.videoStats)
                .presentationDetents([.medium])
        }
    }

    private func portrait(subtitle: String) -> some View {
        VStack(spacing: 18) {
            ZStack {
                if call.phase != .active {
                    PulsingRings(color: .white)
                        .frame(width: 150, height: 150)
                }
                Avatar(name: contactName, fingerprint: call.fingerprint, size: 120)
            }
            .frame(width: 220, height: 220)
            VStack(spacing: 6) {
                Text(contactName)
                    .font(.title.weight(.semibold))
                    .foregroundStyle(.white)
                Text(subtitle)
                    .font(.subheadline)
                    .foregroundStyle(.white.opacity(0.7))
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 40)
                    .accessibilityIdentifier("callStatus")
            }
        }
        .padding(.bottom, 120)
    }

    private var topBar: some View {
        HStack {
            Label {
                Text(call.video ? "Video call over Tor" : "Call over Tor")
            } icon: {
                Image(systemName: "lock.fill")
            }
            .font(.caption.weight(.semibold))
            .foregroundStyle(.white.opacity(0.85))
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
            .background(Capsule().fill(.ultraThinMaterial))
            Spacer()
            if call.phase == .active, let connected = call.connectedAt {
                TimelineView(.periodic(from: connected, by: 1)) { context in
                    Text(Format.duration(context.date.timeIntervalSince(connected)))
                        .font(.callout.monospacedDigit().weight(.semibold))
                        .foregroundStyle(.white)
                }
                .accessibilityIdentifier("callTimer")
            }
            Button {
                showingDetails = true
            } label: {
                Image(systemName: "info.circle")
                    .font(.title3)
                    .foregroundStyle(.white.opacity(0.85))
                    .padding(8)
            }
            .accessibilityLabel("Call details")
            .accessibilityIdentifier("callDetailsButton")
        }
        .padding(.horizontal, 20)
        .padding(.top, 8)
    }

    private var controls: some View {
        HStack(spacing: 22) {
            if call.phase == .active {
                // Mute, not push-to-talk: the microphone is open both ways for
                // the whole call. Muting stops the microphone, not the emission
                // — silence frames go out on the same cadence, so the traffic
                // shape of a muted call and a talking one are identical.
                CallControl(
                    systemImage: isMuted ? "mic.slash.fill" : "mic.fill",
                    label: isMuted ? "Unmute" : "Mute", isOn: isMuted
                ) { isMuted.toggle() }
                .accessibilityIdentifier("muteButton")
                if call.video {
                    CallControl(
                        systemImage: state.isCameraOn ? "video.fill" : "video.slash.fill",
                        label: state.isCameraOn ? "Camera" : "Camera off", isOn: !state.isCameraOn
                    ) { state.toggleCamera() }
                    .accessibilityIdentifier("cameraButton")
                    CallControl(systemImage: "arrow.triangle.2.circlepath.camera", label: "Flip") {
                        state.flipCamera()
                    }
                    .disabled(!state.isCameraOn)
                    .accessibilityIdentifier("flipCameraButton")
                }
            }
            CallControl(
                systemImage: "phone.down.fill",
                label: call.phase == .active ? "End" : "Cancel",
                tint: Theme.danger
            ) { onHangUp() }
            .accessibilityIdentifier("endCallButton")
        }
        .padding(.vertical, 22)
        .padding(.horizontal, 26)
        .background(
            Capsule(style: .continuous)
                .fill(.ultraThinMaterial)
                .opacity(call.phase == .active ? 1 : 0))
        .padding(.bottom, 26)
    }

    private var statusLine: String {
        switch call.phase {
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

/// What the call is carrying, for anyone who wants to look — and for the
/// end-to-end tests, which cannot listen.
private struct CallDetails: View {
    @Environment(\.dismiss) private var dismiss
    let call: CallSession
    let stats: CallStats
    let video: CallVideo.VideoStats

    var body: some View {
        NavigationStack {
            List {
                Section("Audio") {
                    row("Sent", "\(stats.sentAudio) frames, \(stats.sentSilence) silent", id: "statsAudioSent")
                    row("Received", "\(stats.receivedAudio) frames, \(stats.receivedSilence) silent", id: "statsAudioReceived")
                    row("Echo cancellation", stats.echoCancellation ? "On" : "Not available here", id: "statsEcho")
                }
                if call.video {
                    Section("Video") {
                        row("Sent", "\(video.sent) frames, \(video.dropped) dropped", id: "statsVideoSent")
                        row("Received", "\(video.received) frames, \(video.shown) shown", id: "statsVideoReceived")
                    }
                }
                Section {
                    Text(
                        "Every frame on the wire is the same size whether anyone is talking, and "
                            + "whether the camera is on — so these numbers are visible only here."
                    )
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                }
            }
            .navigationTitle("Call details")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                        .accessibilityIdentifier("callDetailsDone")
                }
            }
        }
    }

    private func row(_ title: String, _ value: String, id: String) -> some View {
        HStack {
            Text(title)
            Spacer()
            Text(value)
                .foregroundStyle(.secondary)
                .accessibilityIdentifier(id)
        }
    }
}

// MARK: - Video surfaces

/// The other person's picture.
struct RemoteVideoView: UIViewRepresentable {
    let video: CallVideo
    let quarterTurns: Int

    func makeUIView(context: Context) -> RemoteVideoUIView {
        RemoteVideoUIView(layer: video.remoteLayer)
    }

    func updateUIView(_ view: RemoteVideoUIView, context: Context) {
        view.quarterTurns = quarterTurns
    }
}

/// This end's own picture. The camera's preview layer mirrors the front
/// camera itself, as a mirror does; what is sent is never mirrored.
struct LocalVideoView: UIViewRepresentable {
    let video: CallVideo

    func makeUIView(context: Context) -> UIView {
        let container = UIView()
        container.backgroundColor = .black
        let local = video.localView
        local.removeFromSuperview()
        local.frame = container.bounds
        local.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        container.addSubview(local)
        return container
    }

    func updateUIView(_ view: UIView, context: Context) {}
}

// MARK: - The incoming call screen

struct IncomingCallView: View {
    let contactName: String
    let fingerprint: Data
    let isVideo: Bool
    let isVerified: Bool
    var onAnswer: () -> Void
    var onDecline: () -> Void

    var body: some View {
        ZStack {
            Theme.callBackground.ignoresSafeArea()
            VStack(spacing: 22) {
                Spacer()
                ZStack {
                    PulsingRings(color: Theme.accent)
                        .frame(width: 150, height: 150)
                    Avatar(name: contactName, fingerprint: fingerprint, size: 120)
                }
                .frame(width: 230, height: 230)

                VStack(spacing: 8) {
                    Text(contactName)
                        .font(.largeTitle.weight(.semibold))
                        .foregroundStyle(.white)
                    Label(isVideo ? "Void video call" : "Void call", systemImage: isVideo ? "video.fill" : "phone.fill")
                        .font(.subheadline.weight(.medium))
                        .foregroundStyle(.white.opacity(0.75))

                    // FR-UI-03: the trust state is a sentence, not a badge. An
                    // unverified contact on a call is worth saying out loud,
                    // because voice feels like proof of identity and is not.
                    Text(
                        isVerified
                            ? "You've checked their security code."
                            : (isVideo
                                ? "You haven't checked their security code yet. A face and a voice can both be imitated."
                                : "You haven't checked their security code yet. A voice can be imitated.")
                    )
                    .font(.footnote)
                    .foregroundStyle(isVerified ? .white.opacity(0.6) : .white.opacity(0.9))
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 36)
                    .padding(.top, 6)
                    .accessibilityIdentifier("incomingCallTrustNote")
                }

                Spacer()

                HStack(spacing: 70) {
                    CallControl(systemImage: "phone.down.fill", label: "Decline", tint: Theme.danger, diameter: 74) {
                        onDecline()
                    }
                    .accessibilityIdentifier("declineCallButton")
                    CallControl(
                        systemImage: isVideo ? "video.fill" : "phone.fill", label: "Answer", tint: Theme.answer,
                        diameter: 74
                    ) {
                        onAnswer()
                    }
                    .accessibilityIdentifier("answerCallButton")
                }
                .padding(.bottom, 48)
            }
        }
        .preferredColorScheme(.dark)
    }
}

// MARK: - The disclosure

/// Shown before a call connects — placing one or answering one.
///
/// The body text is `void_proto::call::CALL_DISCLOSURE`, and for a video call
/// `VIDEO_CALL_DISCLOSURE` after it, fetched rather than retyped so neither can
/// be softened here. Per non-negotiable #8 the option states its cost, and per
/// FR-UI-03 it does so in sentences rather than a warning triangle nobody
/// reads.
///
/// The confirming button is not "OK". A user who has read this is agreeing to
/// something specific, so the button says what they are agreeing to.
struct CallDisclosureView: View {
    let contactName: String
    let isAnswering: Bool
    var isVideo = false
    var onContinue: () -> Void
    var onCancel: () -> Void

    var body: some View {
        ZStack {
            Theme.callBackground.ignoresSafeArea()
            VStack(alignment: .leading, spacing: 18) {
                HStack(spacing: 12) {
                    Image(systemName: isVideo ? "video.badge.checkmark" : "phone.badge.checkmark")
                        .font(.system(size: 26, weight: .semibold))
                        .foregroundStyle(Theme.accent)
                        .frame(width: 52, height: 52)
                        .background(Circle().fill(Theme.accent.opacity(0.18)))
                    Text(isAnswering ? "Before you answer" : "Before you call")
                        .font(.title2.weight(.semibold))
                        .foregroundStyle(.white)
                }
                .padding(.top, 12)

                ScrollView {
                    VStack(alignment: .leading, spacing: 14) {
                        Text(VoidCore.callDisclosure)
                            .accessibilityIdentifier("callDisclosureText")
                        if isVideo {
                            Text(VoidCore.videoCallDisclosure)
                                .accessibilityIdentifier("videoCallDisclosureText")
                        }
                    }
                    .font(.body)
                    .foregroundStyle(.white.opacity(0.88))
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(18)
                    .background(
                        RoundedRectangle(cornerRadius: 20, style: .continuous)
                            .fill(.white.opacity(0.07)))
                }

                Text(
                    isAnswering
                        ? "Answering tells \(contactName) you're here."
                        : "Calling tells \(contactName) you're here."
                )
                .font(.footnote)
                .foregroundStyle(.white.opacity(0.6))

                VStack(spacing: 10) {
                    Button(action: onContinue) {
                        Text(isAnswering ? "Answer anyway" : (isVideo ? "Start video call" : "Call anyway"))
                    }
                    .buttonStyle(PrimaryButtonStyle())
                    .accessibilityIdentifier("callDisclosureContinue")

                    Button(action: onCancel) {
                        Text("Not now")
                            .font(.headline)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 14)
                            .foregroundStyle(.white.opacity(0.85))
                    }
                    .accessibilityIdentifier("callDisclosureCancel")
                }
            }
            .padding(24)
        }
        .preferredColorScheme(.dark)
    }
}
