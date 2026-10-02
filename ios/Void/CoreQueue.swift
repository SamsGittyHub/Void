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
//  One thread of our own rather than a dispatch queue or a Swift actor, on
//  purpose. These calls block, and an actor runs on Swift's small cooperative
//  thread pool, where parking a thread on the network for minutes starves
//  unrelated work. And the core needs more stack than either gives: see
//  `CoreThread`.

import Foundation

/// Threads that call into the core.
///
/// The core needs more stack than a dispatch queue's thread has. ML-DSA-87
/// keeps its matrices on the stack, and generating an identity overflowed the
/// 512 KiB a dispatch or secondary thread gets on iOS: the first launch on the
/// Simulator died with SIGBUS, "Thread stack size exceeded", inside
/// `ml_dsa::VerifyingKey::new`, before any screen showed. The core's own
/// end-to-end tests, built as the app links them, overflow at 512 KiB and pass
/// at 576.
///
/// So nothing calls the core from `DispatchQueue.global` or a `Task`: engine
/// calls go through `CoreQueue`, and Tor, the relay, and calls each run on a
/// thread from `detach`. The stack is address space reserved up front; only
/// the pages a call touches are ever backed by memory.
enum CoreThread {
    /// 8 MiB: the main thread's size on the Simulator and macOS, and over ten
    /// times what the core was measured to need.
    static let stackSize = 8 << 20

    /// Run `body` on a new thread with `stackSize` of stack.
    static func detach(name: String, qos: QualityOfService, _ body: @escaping @Sendable () -> Void) {
        let thread = Thread(block: body)
        thread.name = name
        thread.stackSize = stackSize
        thread.qualityOfService = qos
        thread.start()
    }
}

final class CoreQueue: @unchecked Sendable {
    let core: VoidCore
    private let executor = Executor()

    init(core: VoidCore) {
        self.core = core
        let executor = self.executor
        CoreThread.detach(name: "app.void.core", qos: .userInitiated) { executor.loop() }
    }

    deinit {
        // Jobs already queued still run; each holds what it needs.
        executor.stop()
    }

    /// Run `body` against the engine on the core thread and await its result.
    func run<T>(_ body: @escaping @Sendable (VoidCore) -> T) async -> T {
        await withCheckedContinuation { continuation in
            executor.submit { [core] in
                continuation.resume(returning: body(core))
            }
        }
    }

    /// As `run`, for engine calls that throw.
    func attempt<T>(_ body: @escaping @Sendable (VoidCore) throws -> T) async throws -> T {
        try await withCheckedThrowingContinuation { continuation in
            executor.submit { [core] in
                continuation.resume(with: Result { try body(core) })
            }
        }
    }

    /// A repeating timer whose handler runs on the core thread, first straight
    /// away, so a tick never overlaps another tick or any other engine call,
    /// and a slow one delays the next rather than piling them up.
    func makeTimer(every interval: TimeInterval, handler: @escaping @Sendable (VoidCore) -> Void) -> Timer {
        let timer = Timer(interval: interval) { [core] in handler(core) }
        executor.schedule(timer)
        return timer
    }

    /// A repeating timer on the core thread. Stops for good on `cancel`.
    final class Timer: @unchecked Sendable {
        fileprivate let interval: TimeInterval
        fileprivate let fire: () -> Void
        /// Guarded by the executor's lock.
        fileprivate var next = Date()
        fileprivate weak var executor: Executor?

        fileprivate init(interval: TimeInterval, fire: @escaping () -> Void) {
            self.interval = interval
            self.fire = fire
        }

        func cancel() {
            executor?.cancel(self)
        }
    }

    /// The core thread's work: queued jobs first, in order, then whichever
    /// timer is due. Sleeps until there is one or the other.
    fileprivate final class Executor: @unchecked Sendable {
        private let condition = NSCondition()
        private var jobs: [() -> Void] = []
        private var timers: [Timer] = []
        private var stopped = false

        func submit(_ job: @escaping () -> Void) {
            condition.lock()
            jobs.append(job)
            condition.signal()
            condition.unlock()
        }

        func schedule(_ timer: Timer) {
            condition.lock()
            timer.executor = self
            timers.append(timer)
            condition.signal()
            condition.unlock()
        }

        func cancel(_ timer: Timer) {
            condition.lock()
            timers.removeAll { $0 === timer }
            condition.signal()
            condition.unlock()
        }

        func stop() {
            condition.lock()
            stopped = true
            condition.signal()
            condition.unlock()
        }

        func loop() {
            while let work = nextWork() {
                work()
            }
        }

        /// The next thing to run, waiting for one; nil once stopped with
        /// nothing left queued.
        private func nextWork() -> (() -> Void)? {
            condition.lock()
            defer { condition.unlock() }
            while true {
                if !jobs.isEmpty {
                    return jobs.removeFirst()
                }
                if stopped {
                    return nil
                }
                let now = Date()
                if let due = timers.min(by: { $0.next < $1.next }) {
                    if due.next <= now {
                        // Measured from now, not from when it was due: a tick
                        // that ran long is followed by one interval's rest,
                        // never by a burst of catch-up ticks.
                        due.next = now.addingTimeInterval(due.interval)
                        return due.fire
                    }
                    _ = condition.wait(until: due.next)
                } else {
                    condition.wait()
                }
            }
        }
    }
}

/// Wall-clock time in the two units the core takes. Every `now` crossing the
/// boundary is in seconds except the scheduler's, which says `Ms` in its name;
/// a millisecond value passed as seconds is refused rather than misread.
enum Clock {
    static var nowSeconds: UInt64 { UInt64(Date().timeIntervalSince1970) }
    static var nowMs: UInt64 { UInt64(Date().timeIntervalSince1970 * 1000) }
}
