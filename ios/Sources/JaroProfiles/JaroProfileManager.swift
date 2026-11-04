// JARO WPF — Phase 6 Native iOS Tunnel Engine
// Module: JaroProfiles (`.jaroprofile` v1.0 & WireGuard `.conf` Importer/Exporter — Priority A)
// Organization: JARO COMPLEMETS

import Foundation
import JaroCore
import JaroSecurity

public enum JaroProfileValidationError: Error, LocalizedError {
    case unsupportedSchemaVersion(String)
    case invalidProfileIdentifier(String)
    case invalidEndpoint(String)
    case invalidMTU(Int)
    case unauthorizedGlobalDefaultRoute(String)
    case plaintextSecretRejected(String)
    case missingWireGuardFields(String)
    case missingSSHFields(String)

    public var errorDescription: String? {
        switch self {
        case .unsupportedSchemaVersion(let ver):
            return "Unsupported .jaroprofile schema_version: \(ver)"
        case .invalidProfileIdentifier(let id):
            return "Invalid profile_id '\(id)'; must match [a-zA-Z0-9][a-zA-Z0-9._-]{1,63}"
        case .invalidEndpoint(let detail):
            return "Invalid tunnel endpoint: \(detail)"
        case .invalidMTU(let mtu):
            return "Invalid MTU \(mtu); expected 1280...1500"
        case .unauthorizedGlobalDefaultRoute(let cidr):
            return "Global default route (\(cidr)) rejected because include_default_route is false"
        case .plaintextSecretRejected(let detail):
            return "Plaintext secret rejected in profile bundle: \(detail)"
        case .missingWireGuardFields(let detail):
            return "WireGuard profile validation failed: \(detail)"
        case .missingSSHFields(let detail):
            return "SSH profile validation failed: \(detail)"
        }
    }
}

/// Manages `.jaroprofile` v1.0 bundles across `JaroApp` and `JaroPacketTunnel` via shared App Group storage,
/// keeping default remote registries strictly empty (`.remoteServerRequired`) and isolating all cryptographic
/// secrets inside `JaroSecretStoreProtocol` (`Keychain`).
public final class JaroProfileManager: @unchecked Sendable {
    private static let globalDefaultCIDRs: Set<String> = [
        "0.0.0.0/0", "::/0", "0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"
    ]
    private static let profileIdRegex = try! NSRegularExpression(
        pattern: "^[a-zA-Z0-9][a-zA-Z0-9._-]{1,63}$",
        options: []
    )

    private let lock = NSLock()
    private let secretStore: JaroSecretStoreProtocol
    private let storageDirectoryURL: URL?
    private var profilesById: [String: JaroPortableProfile] = [:]

    public init(secretStore: JaroSecretStoreProtocol, storageDirectoryURL: URL? = nil) {
        self.secretStore = secretStore
        self.storageDirectoryURL = storageDirectoryURL
        if let dir = storageDirectoryURL {
            try? reloadFromDirectory(dir)
        }
    }

    public func reloadFromDirectory(_ directoryURL: URL) throws {
        let fm = FileManager.default
        guard fm.fileExists(atPath: directoryURL.path) else { return }
        let items = try fm.contentsOfDirectory(at: directoryURL, includingPropertiesForKeys: nil)
        var loaded: [String: JaroPortableProfile] = [:]
        for url in items where url.pathExtension == "jaroprofile" {
            let data = try Data(contentsOf: url)
            let profile = try decodeAndValidatePortableJSON(data)
            loaded[profile.profileId] = profile
        }
        lock.lock()
        profilesById = loaded
        lock.unlock()
    }

    public func listProfiles(
        protocolFilter: JaroTunnelProtocol? = nil,
        authorizedOnly: Bool = false,
        remoteOnly: Bool = false
    ) -> [JaroPortableProfile] {
        lock.lock()
        let values = Array(profilesById.values)
        lock.unlock()

        return values
            .filter { prof in
                if let pf = protocolFilter, prof.tunnelProtocol != pf { return false }
                if authorizedOnly && !prof.authorized { return false }
                if remoteOnly && prof.isLoopback { return false }
                return true
            }
            .sorted { $0.profileId < $1.profileId }
    }

    /// Evaluates remote server readiness honestly: returns `.remoteServerRequired` (NEVER `.connectedVerifiedHTTPS`)
    /// when no authorized remote server profile is registered.
    public func evaluateRemoteReadiness(protocolFilter: JaroTunnelProtocol? = nil) -> JaroTunnelState {
        let remoteAuthorized = listProfiles(
            protocolFilter: protocolFilter,
            authorizedOnly: true,
            remoteOnly: true
        )
        return remoteAuthorized.isEmpty ? .remoteServerRequired : .unverified
    }

    public func upsertProfile(_ profile: JaroPortableProfile, persist: Bool = false) throws {
        try Self.validateProfile(profile)
        lock.lock()
        profilesById[profile.profileId] = profile
        lock.unlock()

        if persist, let dir = storageDirectoryURL {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            let targetURL = dir.appendingPathComponent("\(profile.profileId).jaroprofile")
            let encoded = try exportPortableJSON(profileId: profile.profileId)
            try encoded.write(to: targetURL, options: .atomic)
        }
    }

    public func removeProfile(profileId: String, removeSecretsFromKeychain: Bool = false) throws {
        lock.lock()
        let removed = profilesById.removeValue(forKey: profileId)
        lock.unlock()

        if let dir = storageDirectoryURL {
            let fileURL = dir.appendingPathComponent("\(profileId).jaroprofile")
            try? FileManager.default.removeItem(at: fileURL)
        }
        if removeSecretsFromKeychain, let prof = removed {
            try? secretStore.deleteSecret(forURI: prof.cryptoReferences.keychainSecretRef)
            if let pskURI = prof.cryptoReferences.keychainPskRef {
                try? secretStore.deleteSecret(forURI: pskURI)
            }
        }
    }

    public func exportPortableJSON(profileId: String) throws -> Data {
        lock.lock()
        let found = profilesById[profileId]
        lock.unlock()
        guard let profile = found else {
            throw JaroProfileValidationError.invalidProfileIdentifier(profileId)
        }
        try Self.validateProfile(profile)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return try encoder.encode(profile)
    }

    public func importPortableJSON(_ jsonData: Data, persist: Bool = false) throws -> JaroPortableProfile {
        let profile = try decodeAndValidatePortableJSON(jsonData)
        try upsertProfile(profile, persist: persist)
        return profile
    }

    /// Safely imports a standard WireGuard `.conf` text, storing `PrivateKey` and optional `PresharedKey`
    /// exclusively in `JaroSecretStoreProtocol` (Keychain) while storing only `keychain://` references in `.jaroprofile`.
    public func importWireGuardConf(
        profileId: String,
        displayName: String,
        confText: String,
        authorized: Bool = false,
        allowGlobalRoutes: Bool = false,
        persist: Bool = false
    ) throws -> JaroPortableProfile {
        try Self.validateProfileId(profileId)

        var currentSection = ""
        var iface: [String: String] = [:]
        var peer: [String: String] = [:]

        for rawLine in confText.components(separatedBy: .newlines) {
            let trimmed = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.isEmpty || trimmed.hasPrefix("#") || trimmed.hasPrefix(";") { continue }
            if trimmed.hasPrefix("[") && trimmed.hasSuffix("]") {
                currentSection = String(trimmed.dropFirst().dropLast()).lowercased()
                continue
            }
            guard let eqIdx = trimmed.firstIndex(of: "=") else { continue }
            let key = trimmed[..<eqIdx].trimmingCharacters(in: .whitespaces).lowercased()
            let val = trimmed[trimmed.index(after: eqIdx)...].trimmingCharacters(in: .whitespaces)
            if currentSection == "interface" {
                iface[key] = val
            } else if currentSection == "peer" {
                peer[key] = val
            }
        }

        // Forbid PreUp/PostUp/SaveConfig shell hooks on iOS
        for forbiddenHook in ["preup", "postup", "predown", "postdown", "saveconfig"] {
            if iface[forbiddenHook] != nil {
                throw JaroProfileValidationError.missingWireGuardFields(
                    "Forbidden shell directive '\(forbiddenHook)' in WireGuard config"
                )
            }
        }

        guard let privateKeyB64 = iface["privatekey"],
              JaroCryptoValidators.isValidWireGuardKeyBase64(privateKeyB64) else {
            throw JaroProfileValidationError.missingWireGuardFields("Valid 32-byte Base64 [Interface] PrivateKey required")
        }
        guard let rawAddress = iface["address"]?.split(separator: ",").first.map({ String($0).trimmingCharacters(in: .whitespaces) }),
              !rawAddress.isEmpty else {
            throw JaroProfileValidationError.missingWireGuardFields("[Interface] Address CIDR required")
        }
        guard let peerPubB64 = peer["publickey"],
              JaroCryptoValidators.isValidWireGuardKeyBase64(peerPubB64) else {
            throw JaroProfileValidationError.missingWireGuardFields("Valid 32-byte Base64 [Peer] PublicKey required")
        }
        guard let endpointRaw = peer["endpoint"], let colonIdx = endpointRaw.lastIndex(of: ":") else {
            throw JaroProfileValidationError.invalidEndpoint("WireGuard [Peer] Endpoint host:port required")
        }

        var hostPart = String(endpointRaw[..<colonIdx])
        if hostPart.hasPrefix("[") && hostPart.hasSuffix("]") {
            hostPart = String(hostPart.dropFirst().dropLast())
        }
        let portString = String(endpointRaw[endpointRaw.index(after: colonIdx)...])
        guard let portNum = Int(portString), (1...65535).contains(portNum), !hostPart.isEmpty else {
            throw JaroProfileValidationError.invalidEndpoint(endpointRaw)
        }

        let mtuVal = Int(iface["mtu"] ?? "1420") ?? 1420
        let allowedIPs = (peer["allowedips"] ?? "")
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        guard !allowedIPs.isEmpty else {
            throw JaroProfileValidationError.missingWireGuardFields("[Peer] AllowedIPs required")
        }

        let hasGlobalRoute = allowedIPs.contains { Self.globalDefaultCIDRs.contains($0) }
        if hasGlobalRoute && !allowGlobalRoutes {
            throw JaroProfileValidationError.unauthorizedGlobalDefaultRoute(allowedIPs.joined(separator: ", "))
        }

        let privKeyURI = "keychain://\(JaroConstants.appGroupIdentifier)/wireguard/\(profileId)/private_key"
        try secretStore.storeSecretString(privateKeyB64, forURI: privKeyURI)

        var pskURI: String?
        if let pskB64 = peer["presharedkey"], !pskB64.isEmpty {
            guard JaroCryptoValidators.isValidWireGuardKeyBase64(pskB64) else {
                throw JaroProfileValidationError.missingWireGuardFields("Invalid Base64 [Peer] PresharedKey")
            }
            let uri = "keychain://\(JaroConstants.appGroupIdentifier)/wireguard/\(profileId)/preshared_key"
            try secretStore.storeSecretString(pskB64, forURI: uri)
            pskURI = uri
        }

        let isLoopback = hostPart == "localhost" || hostPart == "::1" || hostPart.hasPrefix("127.")
        let keepalive = peer["persistentkeepalive"].flatMap(Int.init)

        let profile = JaroPortableProfile(
            profileId: profileId,
            displayName: displayName,
            tunnelProtocol: .wireguard,
            host: hostPart,
            port: portNum,
            scope: isLoopback ? "local_loopback" : "remote",
            authorized: authorized,
            includeDefaultRoute: hasGlobalRoute && allowGlobalRoutes,
            includedRoutes: allowedIPs,
            mtu: mtuVal,
            cryptoReferences: JaroCryptoReferences(keychainSecretRef: privKeyURI, keychainPskRef: pskURI),
            wireguard: JaroWireGuardSection(
                tunnelAddressCIDR: rawAddress,
                peerPublicKeyB64: peerPubB64,
                persistentKeepaliveSec: keepalive
            )
        )
        try upsertProfile(profile, persist: persist)
        return profile
    }

    // MARK: - Validation Helpers

    private func decodeAndValidatePortableJSON(_ jsonData: Data) throws -> JaroPortableProfile {
        if let rawText = String(data: jsonData, encoding: .utf8) {
            if rawText.contains("BEGIN OPENSSH PRIVATE KEY") || rawText.contains("BEGIN PRIVATE KEY") {
                throw JaroProfileValidationError.plaintextSecretRejected("PEM/OpenSSH private key detected in JSON")
            }
        }
        let profile = try JSONDecoder().decode(JaroPortableProfile.self, from: jsonData)
        try Self.validateProfile(profile)
        return profile
    }

    public static func validateProfileId(_ id: String) throws {
        let range = NSRange(id.startIndex..<id.endIndex, in: id)
        guard profileIdRegex.firstMatch(in: id, options: [], range: range) != nil else {
            throw JaroProfileValidationError.invalidProfileIdentifier(id)
        }
    }

    public static func validateProfile(_ profile: JaroPortableProfile) throws {
        guard profile.schemaVersion == JaroConstants.schemaVersion else {
            throw JaroProfileValidationError.unsupportedSchemaVersion(profile.schemaVersion)
        }
        try validateProfileId(profile.profileId)
        guard !profile.host.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              (1...65535).contains(profile.port) else {
            throw JaroProfileValidationError.invalidEndpoint("\(profile.host):\(profile.port)")
        }
        guard (1280...1500).contains(profile.mtu) else {
            throw JaroProfileValidationError.invalidMTU(profile.mtu)
        }
        guard profile.cryptoReferences.keychainSecretRef.hasPrefix("keychain://") else {
            throw JaroProfileValidationError.plaintextSecretRejected(
                "keychain_secret_ref must start with 'keychain://'"
            )
        }
        for cidr in profile.includedRoutes where globalDefaultCIDRs.contains(cidr) && !profile.includeDefaultRoute {
            throw JaroProfileValidationError.unauthorizedGlobalDefaultRoute(cidr)
        }

        switch profile.tunnelProtocol {
        case .wireguard:
            guard let wg = profile.wireguard,
                  !wg.tunnelAddressCIDR.isEmpty,
                  JaroCryptoValidators.isValidWireGuardKeyBase64(wg.peerPublicKeyB64) else {
                throw JaroProfileValidationError.missingWireGuardFields(
                    "tunnel_address_cidr and valid 32-byte Base64 peer_public_key_b64 required"
                )
            }
        case .sshSocks5:
            guard let ssh = profile.sshSocks5,
                  !ssh.username.isEmpty,
                  ssh.pinnedHostKeySHA256.hasPrefix("SHA256:"),
                  (1024...65535).contains(ssh.localProxyPort) else {
                throw JaroProfileValidationError.missingSSHFields(
                    "username, 'SHA256:...' pinned_hostkey_sha256, and local_proxy_port (1024..65535) required"
                )
            }
        }
    }
}
