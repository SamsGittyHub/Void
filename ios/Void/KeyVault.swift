//  KeyVault.swift
//
//  The key-encryption key (KEK) this device's database is opened with (D-026).
//
//  The database key is wrapped under a random 32-byte KEK that exists at rest
//  only in protected form:
//
//  - **With a Secure Enclave** — every device this app ships to — the KEK is
//    stored as ciphertext, encrypted to a P-256 key that was generated inside
//    the Enclave, never leaves it, and can only be used after the user proves
//    presence with Face ID, Touch ID or the passcode (FR-ID-02). Launch asks
//    for that once.
//  - **Without one** — the Simulator, or a device with no passcode set, where
//    iOS refuses to create a presence-gated key — the KEK is a Keychain item
//    bound to this device, and the backing is reported as Software so the
//    security screen says so (NFR-COMP-02) instead of claiming hardware
//    protection it does not have.
//
//  `destroy` deletes the Enclave key and both stored forms. That is duress
//  destruction's irreversible step (D-017): without the Enclave key the KEK is
//  unrecoverable, and so is the database. The engine's own half — erasing what
//  the process holds — is `VoidCore.duressDestroy`, called after this.

import Foundation
import LocalAuthentication
import Security

enum KeyVault {
    struct Opened {
        var kek: [UInt8]
        let backing: VaultBacking
    }

    enum Failure: Error, LocalizedError {
        /// The user dismissed the Face ID / passcode prompt.
        case cancelled
        /// The key exists but could not be used or read.
        case unavailable
        /// Something went wrong making a key on first launch.
        case couldNotCreate

        var errorDescription: String? {
            switch self {
            case .cancelled:
                return "Void stays locked until you unlock it."
            case .unavailable:
                return "Void couldn't unlock its key on this device."
            case .couldNotCreate:
                return "Void couldn't create a key on this device."
            }
        }
    }

    private static let enclaveTag = Data("app.void.kek-wrapper".utf8)
    private static let keychainService = "app.void"
    private static let keychainAccount = "kek"
    private static let algorithm = SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM

    /// Where the Enclave-sealed KEK is kept: app-private, excluded from backup
    /// (FR-STOR-05), and unreadable while the device is locked.
    private static var sealedFile: URL {
        get throws { try AppDirectories.support().appendingPathComponent("kek.sealed") }
    }

    /// Release the KEK for this launch, creating it on first launch. May show
    /// the Face ID / passcode prompt and wait for it, so never call this on
    /// the main thread.
    static func openOrCreate(reason: String) throws -> Opened {
        let sealed = try sealedFile
        if FileManager.default.fileExists(atPath: sealed.path) {
            return Opened(kek: try unseal(Data(contentsOf: sealed), reason: reason), backing: .secureEnclave)
        }
        if let kek = readKeychainKek() {
            return Opened(kek: kek, backing: .software)
        }
        return try create()
    }

    /// Delete the Enclave key and every stored form of the KEK. Irreversible.
    static func destroy() {
        SecItemDelete(
            [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: enclaveTag,
            ] as CFDictionary)
        SecItemDelete(keychainQuery() as CFDictionary)
        if let sealed = try? sealedFile {
            try? FileManager.default.removeItem(at: sealed)
        }
    }

    // MARK: First launch

    private static func create() throws -> Opened {
        // iOS keeps Keychain items — Enclave keys included — after an app is
        // deleted, while its files go. A key left by an earlier install would
        // share this tag and could be the one found at the next launch, which
        // cannot open the new sealed key. Nothing it sealed survives, so clear it.
        SecItemDelete(
            [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: enclaveTag,
            ] as CFDictionary)
        var kek = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, kek.count, &kek) == errSecSuccess else {
            throw Failure.couldNotCreate
        }
        #if !targetEnvironment(simulator)
            if let sealedKek = sealToNewEnclaveKey(kek) {
                let url = try sealedFile
                try sealedKek.write(to: url, options: [.atomic, .completeFileProtection])
                return Opened(kek: kek, backing: .secureEnclave)
            }
        #endif
        guard storeKeychainKek(kek) else {
            for i in kek.indices { kek[i] = 0 }
            throw Failure.couldNotCreate
        }
        return Opened(kek: kek, backing: .software)
    }

    /// Generate a presence-gated key in the Secure Enclave and encrypt `kek` to
    /// it. `nil` where the device cannot make such a key.
    private static func sealToNewEnclaveKey(_ kek: [UInt8]) -> Data? {
        guard
            let access = SecAccessControlCreateWithFlags(
                nil,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                [.privateKeyUsage, .userPresence],
                nil
            )
        else { return nil }
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: enclaveTag,
                kSecAttrAccessControl as String: access,
            ],
        ]
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error),
            let publicKey = SecKeyCopyPublicKey(privateKey),
            SecKeyIsAlgorithmSupported(publicKey, .encrypt, algorithm),
            let sealed = SecKeyCreateEncryptedData(publicKey, algorithm, Data(kek) as CFData, &error)
        else {
            // Leave nothing half-made behind for the next launch to trip on.
            SecItemDelete(
                [
                    kSecClass as String: kSecClassKey,
                    kSecAttrApplicationTag as String: enclaveTag,
                ] as CFDictionary)
            return nil
        }
        return sealed as Data
    }

    // MARK: Later launches

    private static func unseal(_ sealed: Data, reason: String) throws -> [UInt8] {
        let context = LAContext()
        context.localizedReason = reason
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: enclaveTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
            kSecUseAuthenticationContext as String: context,
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess, let item,
            CFGetTypeID(item) == SecKeyGetTypeID()
        else { throw Failure.unavailable }
        let privateKey = item as! SecKey
        var error: Unmanaged<CFError>?
        guard let plain = SecKeyCreateDecryptedData(privateKey, algorithm, sealed as CFData, &error) else {
            let code = error.map { CFErrorGetCode($0.takeRetainedValue()) } ?? 0
            if code == Int(errSecUserCanceled) || code == LAError.userCancel.rawValue
                || code == LAError.appCancel.rawValue || code == LAError.systemCancel.rawValue
            {
                throw Failure.cancelled
            }
            throw Failure.unavailable
        }
        let kek = [UInt8](plain as Data)
        guard kek.count == 32 else { throw Failure.unavailable }
        return kek
    }

    // MARK: Keychain fallback

    private static func keychainQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
        ]
    }

    private static func readKeychainKek() -> [UInt8]? {
        var query = keychainQuery()
        query[kSecReturnData as String] = true
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
            let data = item as? Data, data.count == 32
        else { return nil }
        return [UInt8](data)
    }

    private static func storeKeychainKek(_ kek: [UInt8]) -> Bool {
        var attributes = keychainQuery()
        attributes[kSecValueData as String] = Data(kek)
        // Never leaves this device: not in backups, not in iCloud Keychain.
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        SecItemDelete(keychainQuery() as CFDictionary)
        return SecItemAdd(attributes as CFDictionary, nil) == errSecSuccess
    }
}
