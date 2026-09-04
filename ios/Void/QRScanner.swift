//  QRScanner.swift
//
//  Reads back what QRCode.swift's carousel produces — the other half of
//  FR-DISC-01. VisionKit's `DataScannerViewController` (iOS 16+, matching
//  NFR-COMP-01) does the actual barcode recognition on-device; this file
//  just tracks which `VOID1/i/n/...` chunks have been seen and reassembles
//  the original invite link once every index from 1 to n has landed. A
//  steady hand rarely gets all of them in one continuous scan, so partial
//  progress persists across frames rather than resetting on every miss.

import SwiftUI
import VisionKit

enum QRReassembler {
    struct Frame {
        let index: Int
        let total: Int
        let data: String
    }

    /// Parses one scanned frame's payload. `nil` means it wasn't one of
    /// ours — a stray QR code in view, not a corrupt scan.
    static func parse(_ payload: String) -> Frame? {
        let parts = payload.split(separator: "/", maxSplits: 3, omittingEmptySubsequences: false)
        guard parts.count == 4, parts[0] == "VOID1",
            let index = Int(parts[1]), let total = Int(parts[2]),
            index >= 1, total >= 1, index <= total
        else { return nil }
        return Frame(index: index, total: total, data: String(parts[3]))
    }

    /// Joins collected frames back into the original link once all of
    /// `1...total` are present. Frames need not be complete or in order.
    static func reassemble(_ frames: [Int: Frame]) -> String? {
        guard let total = frames.values.first?.total,
            frames.values.allSatisfy({ $0.total == total }),
            (1...total).allSatisfy({ frames[$0] != nil })
        else { return nil }
        return (1...total).compactMap { frames[$0]?.data }.joined()
    }
}

@MainActor
final class ScanProgress: ObservableObject {
    @Published fileprivate var frames: [Int: QRReassembler.Frame] = [:]
    @Published var completedLink: String?

    var scannedCount: Int { frames.count }
    var totalCount: Int? { frames.values.first?.total }

    fileprivate func ingest(_ payload: String) {
        guard completedLink == nil, let frame = QRReassembler.parse(payload) else { return }
        // A code reporting a different total means a different invite (or a
        // restarted one) is now in view — start that set over rather than
        // silently mixing chunks from two links into one link.
        if let existingTotal = totalCount, existingTotal != frame.total {
            frames.removeAll()
        }
        frames[frame.index] = frame
        if let joined = QRReassembler.reassemble(frames) {
            completedLink = joined
        }
    }
}

struct InviteScannerView: UIViewControllerRepresentable {
    @ObservedObject var progress: ScanProgress

    func makeUIViewController(context: Context) -> DataScannerViewController {
        let controller = DataScannerViewController(
            recognizedDataTypes: [.barcode(symbologies: [.qr])],
            qualityLevel: .balanced,
            recognizesMultipleItems: true,
            isHighFrameRateTrackingEnabled: false,
            isHighlightingEnabled: true
        )
        controller.delegate = context.coordinator
        try? controller.startScanning()
        return controller
    }

    func updateUIViewController(_ controller: DataScannerViewController, context: Context) {}

    func makeCoordinator() -> Coordinator { Coordinator(progress: progress) }

    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        let progress: ScanProgress
        init(progress: ScanProgress) { self.progress = progress }

        func dataScanner(
            _ dataScanner: DataScannerViewController,
            didAdd addedItems: [RecognizedItem],
            allItems: [RecognizedItem]
        ) {
            for item in addedItems {
                if case let .barcode(barcode) = item, let payload = barcode.payloadStringValue {
                    Task { @MainActor in progress.ingest(payload) }
                }
            }
        }
    }
}

/// The sheet presented from "Scan a QR code": live camera behind a progress
/// readout, closing itself the moment the last chunk lands. Falls back to a
/// plain message — never a silent dead end — on hardware/OS combinations
/// `DataScannerViewController` doesn't support (the Simulator has no camera
/// at all, and older devices lack the on-device model it depends on).
struct InviteScanSheet: View {
    var onScanned: (String) -> Void

    @Environment(\.dismiss) private var dismiss
    @StateObject private var progress = ScanProgress()

    var body: some View {
        NavigationStack {
            Group {
                if DataScannerViewController.isSupported && DataScannerViewController.isAvailable {
                    ZStack(alignment: .bottom) {
                        InviteScannerView(progress: progress)
                            .ignoresSafeArea()

                        Text(statusText)
                            .font(.subheadline.monospacedDigit())
                            .padding(.horizontal, 16)
                            .padding(.vertical, 8)
                            .background(.ultraThinMaterial, in: Capsule())
                            .padding(.bottom, 24)
                    }
                } else {
                    VStack(spacing: 12) {
                        Image(systemName: "camera.fill")
                            .font(.largeTitle)
                            .foregroundStyle(.secondary)
                        Text("Scanning isn't available on this device")
                            .font(.headline)
                        Text("Paste the invite link instead.")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                    .padding()
                }
            }
            .navigationTitle("Scan invite")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
            .onChange(of: progress.completedLink) { link in
                if let link {
                    onScanned(link)
                    dismiss()
                }
            }
        }
    }

    private var statusText: String {
        if let total = progress.totalCount {
            return "\(progress.scannedCount) of \(total) codes scanned"
        }
        return "Point the camera at the first code"
    }
}
