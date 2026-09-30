//  CoreQueue.swift
//
//  Every call into the engine runs here, one at a time, and never on the main
//  thread.
//
//  The engine holds its lock for a whole tick, and a tick can wait on the
//  network — a retrieval over a stalled circuit waits up to two minutes for
//  the relay. Ticking from a main-thread timer, as this app used to, froze the
//  interface for exactly that long. Now the main thread only ever awaits a
//  result.
//
//  A serial dispatch queue rather than a Swift actor, on purpose: these calls
//  block. An actor runs on Swift's small cooperative thread pool, and parking
//  one of those threads on the network for minutes starves unrelated work.
//  Tor bootstrap and call media do not touch the engine's lock and run on
//  their own threads, not here.

import Foundation

final class CoreQueue: @unchecked Sendable {
    let core: VoidCore
    private let queue = DispatchQueue(label: "app.void.core", qos: .userInitiated)

    init(core: VoidCore) {
        self.core = core
    }

    /// Run `body` against the engine on the core queue and await its result.
    func run<T>(_ body: @escaping @Sendable (VoidCore) -> T) async -> T {
        await withCheckedContinuation { continuation in
            queue.async {
                continuation.resume(returning: body(self.core))
            }
        }
    }

    /// As `run`, for engine calls that throw.
    func attempt<T>(_ body: @escaping @Sendable (VoidCore) throws -> T) async throws -> T {
        try await withCheckedThrowingContinuation { continuation in
            queue.async {
                continuation.resume(with: Result { try body(self.core) })
            }
        }
    }

    /// A repeating timer whose handler runs on the core queue, so a tick never
    /// overlaps another tick or any other engine call, and a slow one delays
    /// the next rather than piling them up.
    func makeTimer(every interval: DispatchTimeInterval, handler: @escaping @Sendable (VoidCore) -> Void)
        -> DispatchSourceTimer
    {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now(), repeating: interval, leeway: .milliseconds(100))
        timer.setEventHandler { [core] in handler(core) }
        timer.resume()
        return timer
    }
}

/// Wall-clock time in the two units the core takes. Every `now` crossing the
/// boundary is in seconds except the scheduler's, which says `Ms` in its name;
/// a millisecond value passed as seconds is refused rather than misread.
enum Clock {
    static var nowSeconds: UInt64 { UInt64(Date().timeIntervalSince1970) }
    static var nowMs: UInt64 { UInt64(Date().timeIntervalSince1970 * 1000) }
}
