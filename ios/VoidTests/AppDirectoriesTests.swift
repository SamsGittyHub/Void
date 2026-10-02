//  AppDirectoriesTests.swift
//
//  Arti will not bootstrap from a state or cache directory that anyone but its
//  owner can read, and `FileManager` creates directories 0755. The app was
//  offline on every launch for exactly that reason, with nothing on screen to
//  say why, so the permissions are pinned here.

import XCTest

@testable import Void

final class AppDirectoriesTests: XCTestCase {
    func testTorDirectoriesAreOwnerOnly() throws {
        for directory in [try AppDirectories.torState(), try AppDirectories.torCache()] {
            let attributes = try FileManager.default.attributesOfItem(atPath: directory.path)
            let permissions = try XCTUnwrap(attributes[.posixPermissions] as? NSNumber).intValue
            XCTAssertEqual(permissions & 0o777, 0o700, directory.lastPathComponent)
        }
    }

    func testADirectoryLeftOpenByAnEarlierBuildIsClosedAgain() throws {
        let state = try AppDirectories.torState()
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: state.path)
        _ = try AppDirectories.torState()
        let attributes = try FileManager.default.attributesOfItem(atPath: state.path)
        XCTAssertEqual(try XCTUnwrap(attributes[.posixPermissions] as? NSNumber).intValue & 0o777, 0o700)
    }
}
