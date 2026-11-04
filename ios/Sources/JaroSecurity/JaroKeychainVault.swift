// JARO WPF — Phase 6 Native iOS Tunnel Engine
// Module: JaroSecurity (Keychain Vault & Shared Access Group Storage)
// Organization: JARO COMPLEMETS

import Foundation
import JaroCore
#if canImport(Security)
import Security
#endif

public enum JaroKeychainError: Error, LocalizedError {
    case invalidKeychainURI(String)
    case itemNotFound(String)
    case unexpectedOSStatus(Int32)
    case encodingError
    case securityFrameworkUnavailable

    public var errorDescription: String? {
        switch self {
        case .invalidKeychainURI(let uri):
            return "Invalid keychain:// reference URI: \(uri)"
        case .itemNotFound(let ref):
            return "Secret item not found in Keychain vault: \(ref)"
        case .unexpectedOSStatus(let status):
            return "iOS Keychain OSStatus error: \(status)"
        case .encodingError:
            return "Failed to encode/decode UTF-8 secret material"
        case .securityFrameworkUnavailable:
            return "Apple Security.framework is only available on iOS/macOS"
        }
    }
}

/// Abstraction over Keychain storage so `JaroProfiles` and unit tests can verify secret separation deterministically.
public protocol JaroSecretStoreProtocol: Sendable {
    func storeSecret(_ secretData: Data, forURI keychainURI: String) throws
    func loadSecret(forURI keychainURI: String) throws -> Data
    func deleteSecret(forURI keychainURI: String) throws
}

extension JaroSecretStoreProtocol {
    public func storeSecretString(_ secret: String, forURI keychainURI: String) throws {
        guard let data = secret.data(using: .utf8) else {
            throw JaroKeychainError.encodingError
        }
        try storeSecret(data, forURI: keychainURI)
    }

    public func loadSecretString(forURI keychainURI: String) throws -> String {
        let data = try loadSecret(forURI: keychainURI)
        guard let str = String(data: data, encoding: .utf8) else {
            throw JaroKeychainError.encodingError
        }
        return str
    }
}

/// Parses canonical `keychain://<accessGroup>/<service>/<profileId>/<itemName>` references.
public struct JaroKeychainReference: Equatable, Sendable {
    public let accessGroup: String
    public let service: String
    public let account: String
    public let rawURI: String

    public init(uri: String) throws {
        let trimmed = uri.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.hasPrefix("keychain://") else {
            throw JaroKeychainError.invalidKeychainURI(uri)
        }
        let withoutScheme = String(trimmed.dropFirst("keychain://".count))
        let segments = withoutScheme.split(separator: "/").map(String.init)
        guard segments.count >= 3 else {
            throw JaroKeychainError.invalidKeychainURI(uri)
        }
        self.accessGroup = segments[0]
        self.service = "com.jarocomplements.jarowpf.\(segments[1])"
        self.account = segments.dropFirst(2).joined(separator: "/")
        self.rawURI = trimmed
    }
}

/// Production iOS/macOS Keychain store using `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`
/// so `NEPacketTunnelProvider` can reconnect while the iPhone screen is locked, while preventing
/// unencrypted cloud/device-migration key leakage.
public final class JaroKeychainVault: JaroSecretStoreProtocol, @unchecked Sendable {
    private let appIdentifierPrefix: String?

    public init(appIdentifierPrefix: String? = nil) {
        self.appIdentifierPrefix = appIdentifierPrefix
    }

    public func storeSecret(_ secretData: Data, forURI keychainURI: String) throws {
        let ref = try JaroKeychainReference(uri: keychainURI)
        #if canImport(Security)
        var baseQuery = makeBaseQuery(for: ref)
        SecItemDelete(baseQuery as CFDictionary)

        baseQuery[kSecValueData as String] = secretData
        baseQuery[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(baseQuery as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw JaroKeychainError.unexpectedOSStatus(status)
        }
        #else
        _ = (ref, secretData)
        throw JaroKeychainError.securityFrameworkUnavailable
        #endif
    }

    public func loadSecret(forURI keychainURI: String) throws -> Data {
        let ref = try JaroKeychainReference(uri: keychainURI)
        #if canImport(Security)
        var query = makeBaseQuery(for: ref)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound {
            throw JaroKeychainError.itemNotFound(ref.rawURI)
        }
        guard status == errSecSuccess, let data = item as? Data else {
            throw JaroKeychainError.unexpectedOSStatus(status)
        }
        return data
        #else
        throw JaroKeychainError.securityFrameworkUnavailable
        #endif
    }

    public func deleteSecret(forURI keychainURI: String) throws {
        let ref = try JaroKeychainReference(uri: keychainURI)
        #if canImport(Security)
        let query = makeBaseQuery(for: ref)
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw JaroKeychainError.unexpectedOSStatus(status)
        }
        #else
        throw JaroKeychainError.securityFrameworkUnavailable
        #endif
    }

    #if canImport(Security)
    private func makeBaseQuery(for ref: JaroKeychainReference) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: ref.service,
            kSecAttrAccount as String: ref.account,
        ]
        if let prefix = appIdentifierPrefix, !prefix.isEmpty {
            query[kSecAttrAccessGroup as String] = "\(prefix)\(ref.accessGroup)"
        }
        return query
    }
    #endif
}

/// Isolated in-memory vault used for unit tests without touching device Keychain state.
public final class JaroInMemorySecretVault: JaroSecretStoreProtocol, @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [String: Data] = [:]

    public init() {}

    public func storeSecret(_ secretData: Data, forURI keychainURI: String) throws {
        let ref = try JaroKeychainReference(uri: keychainURI)
        lock.lock()
        defer { lock.unlock() }
        storage[ref.rawURI] = secretData
    }

    public func loadSecret(forURI keychainURI: String) throws -> Data {
        let ref = try JaroKeychainReference(uri: keychainURI)
        lock.lock()
        defer { lock.unlock() }
        guard let val = storage[ref.rawURI] else {
            throw JaroKeychainError.itemNotFound(ref.rawURI)
        }
        return val
    }

    public func deleteSecret(forURI keychainURI: String) throws {
        let ref = try JaroKeychainReference(uri: keychainURI)
        lock.lock()
        defer { lock.unlock() }
        storage.removeValue(forKey: ref.rawURI)
    }
}
