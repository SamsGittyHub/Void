//  AppDirectories.swift
//
//  Where Void keeps things on disk. Every directory here is app-private and
//  excluded from backup (FR-STOR-05), and the app's entitlement sets
//  `NSFileProtectionComplete`, so none of it is readable while the phone is
//  locked.

import Foundation

/// The app's private directories, created on first use.
enum AppDirectories {
    /// Application Support/Void: the database and the sealed key. Excluded from
    /// backup (FR-STOR-05); the entitlement's `NSFileProtectionComplete` makes
    /// it unreadable while the device is locked.
    static func support() throws -> URL {
        let base = try FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        return try excludedFromBackup(base.appendingPathComponent("Void", isDirectory: true))
    }

    /// Where the engine keeps its database.
    static func database() throws -> URL {
        try excludedFromBackup(support().appendingPathComponent("data", isDirectory: true))
    }

    /// Arti's own state (guards, consensus) — also private and not backed up.
    static func torState() throws -> URL {
        try excludedFromBackup(support().appendingPathComponent("tor-state", isDirectory: true))
    }

    /// Arti's cache, which it can rebuild.
    static func torCache() throws -> URL {
        let base = try FileManager.default.url(
            for: .cachesDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        return try excludedFromBackup(base.appendingPathComponent("Void/tor-cache", isDirectory: true))
    }

    /// A fresh directory for one call's onion-service keys, deleted when the
    /// call ends (D-024).
    static func callKeys() -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent(
            "void-call-\(UUID().uuidString)", isDirectory: true)
    }

    private static func excludedFromBackup(_ url: URL) throws -> URL {
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        var marked = url
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try marked.setResourceValues(values)
        return url
    }
}
