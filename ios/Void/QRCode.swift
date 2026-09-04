//  QRCode.swift
//
//  QR rendering for invite links (FR-DISC-01).
//
//  ## Why one link needs several QR codes
//
//  A Void invite link carries a full prekey bundle: an ML-DSA-87 identity key
//  (2,592 bytes) and its hybrid signature (~4,691 bytes) alongside the
//  classical X25519/Ed25519 material and the ML-KEM-1024 prekey (1,568
//  bytes) — there is no directory to look any of that up from later, so it
//  all has to travel in the invite itself. Base32-encoded, a real link is
//  around 14,600 characters. The largest QR code that exists (version 40,
//  error correction L) holds about 4,296 alphanumeric characters — roughly a
//  third of that, at the size and error-correction level least likely to
//  actually scan. One QR code was never going to hold this.
//
//  The fix used everywhere this problem shows up in practice — hardware
//  wallets moving signed transactions the same way — is a *sequence* of QR
//  codes, each small enough to scan reliably, that a reader reassembles in
//  order. `QRChunker` produces that sequence; `InviteQRCodeCarousel` displays
//  it as swipeable pages. What does not exist yet, on either platform in
//  this revision, is a scanner that reads the sequence back in — see
//  `docs/DECISIONS.md`'s entry on this. Until one exists, the link text
//  itself (share sheet, copy, paste) is the reliable path; the QR carousel
//  is real and scannable today, just not yet round-trippable inside Void.

import CoreImage.CIFilterBuiltins
import SwiftUI

enum QRChunker {
    /// Characters per frame. Base32 (Void's invite alphabet) is entirely
    /// within QR's alphanumeric character set, so this could go as high as
    /// ~4,200 before exceeding a single code's hard limit — but a code that
    /// dense is hard to scan reliably from a phone screen at arm's length.
    /// 1,200 keeps each frame at a moderate QR version (roughly 20–22) that
    /// scans comfortably, at the cost of more frames to swipe through.
    static let chunkSize = 1200

    /// Split `payload` into self-describing, ordered chunks: `VOID1/i/n/data`.
    /// The header is small and fixed-format on purpose — a future scanner
    /// needs to recognise a frame and its position without decoding the
    /// payload first.
    static func chunks(for payload: String) -> [String] {
        let characters = Array(payload)
        guard !characters.isEmpty else { return [] }
        let total = Int((Double(characters.count) / Double(chunkSize)).rounded(.up))
        return (0..<total).map { i in
            let start = i * chunkSize
            let end = min(start + chunkSize, characters.count)
            let piece = String(characters[start..<end])
            return "VOID1/\(i + 1)/\(total)/\(piece)"
        }
    }
}

/// One QR code image, rendered from CoreImage's built-in generator — no
/// third-party dependency, matching NFR-SEC-07's bar for the trusted path
/// even though this is a display-only concern, not a cryptographic one.
private struct QRCodeImage: View {
    let content: String

    var body: some View {
        if let uiImage = Self.render(content) {
            Image(uiImage: uiImage)
                .interpolation(.none)
                .resizable()
                .scaledToFit()
        } else {
            VStack(spacing: 8) {
                Image(systemName: "exclamationmark.triangle")
                    .font(.title)
                    .foregroundStyle(.orange)
                Text("Could not render this code")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, minHeight: 200)
        }
    }

    private static func render(_ text: String) -> UIImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage else { return nil }
        // The raw output is one point per module (often under 100px square);
        // scale up with nearest-neighbour so edges stay crisp rather than
        // blurring into an unscannable smear.
        let scale = 512.0 / output.extent.width
        let scaled = output.transformed(by: CGAffineTransform(scaleX: scale, y: scale))
        let context = CIContext()
        guard let cgImage = context.createCGImage(scaled, from: scaled.extent) else { return nil }
        return UIImage(cgImage: cgImage)
    }
}

/// Swipeable pages through every QR code a link needs. Shows one page
/// directly, without paging chrome, when the whole link fits in one code.
struct InviteQRCodeCarousel: View {
    let link: String

    private var frames: [String] { QRChunker.chunks(for: link) }

    var body: some View {
        VStack(spacing: 8) {
            if frames.count > 1 {
                TabView {
                    ForEach(Array(frames.enumerated()), id: \.offset) { _, frame in
                        QRCodeImage(content: frame)
                            .padding(8)
                    }
                }
                .tabViewStyle(.page(indexDisplayMode: .always))
                .frame(height: 280)

                Text(
                    "This invite needs \(frames.count) codes because of the post-quantum keys "
                        + "involved — swipe through all of them, or share the link below instead."
                )
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            } else if let only = frames.first {
                QRCodeImage(content: only)
                    .frame(height: 240)
                Text("Share this code, or the link below, with one person.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }
}
