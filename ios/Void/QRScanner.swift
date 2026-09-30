//  QRScanner.swift
//
//  Reads an invitation's QR code — the other half of FR-DISC-01. VisionKit's
//  `DataScannerViewController` (iOS 16+, matching NFR-COMP-01) does the
//  recognition on-device; this file hands back the first `void://` code it
//  sees. An invitation is one code (D-027), so there is nothing to reassemble.

import SwiftUI
import VisionKit

/// Whether a scanned payload is a Void link at all. Everything else in view —
/// a menu, a parking meter — is ignored rather than reported as an error.
func isVoidLink(_ payload: String) -> Bool {
    payload.trimmingCharacters(in: .whitespacesAndNewlines).lowercased().hasPrefix("void://")
}

struct InviteScannerView: UIViewControllerRepresentable {
    var onScanned: (String) -> Void
    var onFailed: (String) -> Void

    func makeUIViewController(context: Context) -> DataScannerViewController {
        let controller = DataScannerViewController(
            recognizedDataTypes: [.barcode(symbologies: [.qr])],
            qualityLevel: .balanced,
            recognizesMultipleItems: false,
            isHighFrameRateTrackingEnabled: false,
            isHighlightingEnabled: true
        )
        controller.delegate = context.coordinator
        do {
            try controller.startScanning()
        } catch {
            // Never a silent black screen: say why, and offer the other way in.
            DispatchQueue.main.async {
                onFailed("The camera couldn't start. Paste the invitation link instead.")
            }
        }
        return controller
    }

    func updateUIViewController(_ controller: DataScannerViewController, context: Context) {}

    static func dismantleUIViewController(_ controller: DataScannerViewController, coordinator: Coordinator) {
        controller.stopScanning()
    }

    func makeCoordinator() -> Coordinator { Coordinator(onScanned: onScanned) }

    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        private let onScanned: (String) -> Void
        private var done = false

        init(onScanned: @escaping (String) -> Void) {
            self.onScanned = onScanned
        }

        func dataScanner(
            _ dataScanner: DataScannerViewController,
            didAdd addedItems: [RecognizedItem],
            allItems: [RecognizedItem]
        ) {
            guard !done else { return }
            for item in addedItems {
                if case let .barcode(barcode) = item, let payload = barcode.payloadStringValue,
                    isVoidLink(payload)
                {
                    done = true
                    dataScanner.stopScanning()
                    onScanned(payload.trimmingCharacters(in: .whitespacesAndNewlines))
                    return
                }
            }
        }
    }
}

/// The sheet presented from "Scan a code": live camera, closing itself the
/// moment an invitation is in view. Falls back to a plain message — never a
/// silent dead end — on hardware/OS combinations `DataScannerViewController`
/// doesn't support (the Simulator has no camera at all, and older devices
/// lack the on-device model it depends on), and when the camera won't start.
struct InviteScanSheet: View {
    var onScanned: (String) -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var failure: String?

    var body: some View {
        NavigationStack {
            Group {
                if let failure {
                    unavailable(failure)
                } else if DataScannerViewController.isSupported && DataScannerViewController.isAvailable {
                    ZStack(alignment: .bottom) {
                        InviteScannerView(
                            onScanned: { link in
                                onScanned(link)
                                dismiss()
                            },
                            onFailed: { failure = $0 }
                        )
                        .ignoresSafeArea()

                        Text("Point the camera at their Void code")
                            .font(.subheadline)
                            .padding(.horizontal, 16)
                            .padding(.vertical, 8)
                            .background(.ultraThinMaterial, in: Capsule())
                            .padding(.bottom, 24)
                    }
                } else {
                    unavailable("Scanning isn't available on this device. Paste the invitation link instead.")
                }
            }
            .navigationTitle("Scan a code")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
        }
    }

    private func unavailable(_ message: String) -> some View {
        VStack(spacing: 12) {
            Image(systemName: "camera.fill")
                .font(.largeTitle)
                .foregroundStyle(.secondary)
            Text(message)
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding()
    }
}
