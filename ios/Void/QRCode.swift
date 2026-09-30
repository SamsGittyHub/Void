//  QRCode.swift
//
//  QR rendering for invitation links (FR-DISC-01).
//
//  An invitation link is short — `void://i/<relay>#<secret>`, about 130
//  characters — because the invitation itself is parked, encrypted, on the
//  relay (D-027). So it is one small QR code, easy to scan at arm's length.
//  It used to be the whole signed prekey bundle, about 14,600 characters and
//  thirteen codes to swipe through; full `void://c/` links still open, they are
//  just never shown as a code.

import CoreImage.CIFilterBuiltins
import SwiftUI

/// One QR code image, rendered from CoreImage's built-in generator — no
/// third-party dependency, matching NFR-SEC-07's bar for the trusted path
/// even though this is a display-only concern, not a cryptographic one.
struct QRCodeImage: View {
    let content: String

    var body: some View {
        if let uiImage = Self.render(content) {
            Image(uiImage: uiImage)
                .interpolation(.none)
                .resizable()
                .scaledToFit()
                .accessibilityLabel("QR code for your invitation")
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

    static func render(_ text: String) -> UIImage? {
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
