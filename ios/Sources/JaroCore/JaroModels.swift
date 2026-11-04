// JARO WPF — Phase 6 Native iOS Tunnel Engine
// Module: JaroCore
// Organization: JARO COMPLEMETS

import Foundation

public enum JaroConstants {
    public static let schemaVersion = "1.0.0"
    public static let organization = "JARO COMPLEMETS"
    public static let project = "JARO WPF"
    public static let appGroupIdentifier = "group.com.jarocomplements.jarowpf"
    public static let packetTunnelBundleIdentifier = "com.jarocomplements.jarowpf.PacketTunnel"
    public static let extensionMemoryCeilingMB = 15
    public static let verificationStatus = "UNVERIFIED_ON_PHYSICAL_IPHONE"
}

/// Tunnel protocols supported natively by JARO on iOS without external binaries.
public enum JaroTunnelProtocol: String, Codable, CaseIterable, Sendable {
    case wireguard = "wireguard"
    case sshSocks5 = "ssh_socks5"
}

/// Deterministic tunnel lifecycle states. Notice `.remoteServerRequired` when no remote profile exists.
public enum JaroTunnelState: String, Codable, Sendable {
    case disconnected = "DISCONNECTED"
    case remoteServerRequired = "REMOTE_SERVER_REQUIRED"
    case unverified = "UNVERIFIED"
    case connecting = "CONNECTING"
    case reconnecting = "RECONNECTING"
    case connectedHandshakeOnly = "CONNECTED_HANDSHAKE_ONLY"
    case connectedVerifiedHTTPS = "CONNECTED_VERIFIED_HTTPS"
    case blockedByCostPolicy = "BLOCKED_BY_COST_POLICY"
    case circuitBreakerOpen = "CIRCUIT_BREAKER_OPEN"
    case failed = "FAILED"
}

/// Network path cost classification derived from `NWPathMonitor` + user overrides (never assumes Wi-Fi is free).
public struct JaroPathCostSnapshot: Codable, Equatable, Sendable {
    public let interfaceKind: String
    public let isExpensive: Bool
    public let isConstrained: Bool
    public let userMarkedMetered: Bool?
    public let satisfiesTunnelPolicy: Bool

    public init(
        interfaceKind: String,
        isExpensive: Bool,
        isConstrained: Bool,
        userMarkedMetered: Bool? = nil,
        allowExpensivePaths: Bool = false
    ) {
        self.interfaceKind = interfaceKind
        self.isExpensive = isExpensive
        self.isConstrained = isConstrained
        self.userMarkedMetered = userMarkedMetered
        let effectiveMetered = userMarkedMetered ?? (isExpensive || isConstrained)
        self.satisfiesTunnelPolicy = allowExpensivePaths || !effectiveMetered
    }
}

/// Live traffic and handshake statistics matching Phase 5/6 telemetry requirements (Priority H).
public struct JaroTrafficStats: Codable, Equatable, Sendable {
    public var rxBytes: UInt64
    public var txBytes: UInt64
    public var socks5Connections: UInt64
    public var httpConnectConnections: UInt64
    public var lastHandshakeEpochSec: Int64?
    public var availableExtensionMemoryBytes: UInt64?
    public var updatedUTC: String

    public init(
        rxBytes: UInt64 = 0,
        txBytes: UInt64 = 0,
        socks5Connections: UInt64 = 0,
        httpConnectConnections: UInt64 = 0,
        lastHandshakeEpochSec: Int64? = nil,
        availableExtensionMemoryBytes: UInt64? = nil,
        updatedUTC: String = ISO8601DateFormatter().string(from: Date())
    ) {
        self.rxBytes = rxBytes
        self.txBytes = txBytes
        self.socks5Connections = socks5Connections
        self.httpConnectConnections = httpConnectConnections
        self.lastHandshakeEpochSec = lastHandshakeEpochSec
        self.availableExtensionMemoryBytes = availableExtensionMemoryBytes
        self.updatedUTC = updatedUTC
    }

    public var hasBidirectionalTransfer: Bool {
        rxBytes > 0 && txBytes > 0
    }
}

/// Independent capability matrix matching Phase 4/5 diagnostic precision (never conflates DNS with HTTPS).
public struct JaroCapabilityMatrix: Codable, Equatable, Sendable {
    public var localProxyListening: Bool
    public var sshAuthenticatedSession: Bool
    public var sshVerifiedHTTPS: Bool
    public var wireguardHandshake: Bool
    public var wireguardBidirectionalTransfer: Bool
    public var wireguardVerifiedHTTPS: Bool
    public var captivePortalDetected: Bool

    public init(
        localProxyListening: Bool = false,
        sshAuthenticatedSession: Bool = false,
        sshVerifiedHTTPS: Bool = false,
        wireguardHandshake: Bool = false,
        wireguardBidirectionalTransfer: Bool = false,
        wireguardVerifiedHTTPS: Bool = false,
        captivePortalDetected: Bool = false
    ) {
        self.localProxyListening = localProxyListening
        self.sshAuthenticatedSession = sshAuthenticatedSession
        self.sshVerifiedHTTPS = sshVerifiedHTTPS
        self.wireguardHandshake = wireguardHandshake
        self.wireguardBidirectionalTransfer = wireguardBidirectionalTransfer
        self.wireguardVerifiedHTTPS = wireguardVerifiedHTTPS
        self.captivePortalDetected = captivePortalDetected
    }
}

// MARK: - Canonical `.jaroprofile` v1.0 Schema (Shared Byte-for-Byte with Python `JaroTunnelProfile`)

public struct JaroIOSTargetMetadata: Codable, Equatable, Sendable {
    public let appGroup: String
    public let extensionBundleId: String
    public let extensionMemoryCeilingMb: Int
    public let deviceVerified: Bool
    public let verificationStatus: String

    enum CodingKeys: String, CodingKey {
        case appGroup = "app_group"
        case extensionBundleId = "extension_bundle_id"
        case extensionMemoryCeilingMb = "extension_memory_ceiling_mb"
        case deviceVerified = "device_verified"
        case verificationStatus = "verification_status"
    }

    public init(
        appGroup: String = JaroConstants.appGroupIdentifier,
        extensionBundleId: String = JaroConstants.packetTunnelBundleIdentifier,
        extensionMemoryCeilingMb: Int = JaroConstants.extensionMemoryCeilingMB,
        deviceVerified: Bool = false,
        verificationStatus: String = JaroConstants.verificationStatus
    ) {
        self.appGroup = appGroup
        self.extensionBundleId = extensionBundleId
        self.extensionMemoryCeilingMb = extensionMemoryCeilingMb
        self.deviceVerified = deviceVerified
        self.verificationStatus = verificationStatus
    }
}

public struct JaroCryptoReferences: Codable, Equatable, Sendable {
    public let keychainSecretRef: String
    public let keychainPskRef: String?
    public let keychainAccessibility: String

    enum CodingKeys: String, CodingKey {
        case keychainSecretRef = "keychain_secret_ref"
        case keychainPskRef = "keychain_psk_ref"
        case keychainAccessibility = "keychain_accessibility"
    }

    public init(
        keychainSecretRef: String,
        keychainPskRef: String? = nil,
        keychainAccessibility: String = "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly"
    ) {
        self.keychainSecretRef = keychainSecretRef
        self.keychainPskRef = keychainPskRef
        self.keychainAccessibility = keychainAccessibility
    }
}

public struct JaroWireGuardSection: Codable, Equatable, Sendable {
    public let tunnelAddressCIDR: String
    public let peerPublicKeyB64: String
    public let persistentKeepaliveSec: Int?

    enum CodingKeys: String, CodingKey {
        case tunnelAddressCIDR = "tunnel_address_cidr"
        case peerPublicKeyB64 = "peer_public_key_b64"
        case persistentKeepaliveSec = "persistent_keepalive_s"
    }

    public init(tunnelAddressCIDR: String, peerPublicKeyB64: String, persistentKeepaliveSec: Int? = nil) {
        self.tunnelAddressCIDR = tunnelAddressCIDR
        self.peerPublicKeyB64 = peerPublicKeyB64
        self.persistentKeepaliveSec = persistentKeepaliveSec
    }
}

public struct JaroSSHSocksSection: Codable, Equatable, Sendable {
    public let username: String
    public let pinnedHostKeySHA256: String
    public let localProxyPort: Int
    public let supportsHTTPConnectBridge: Bool

    enum CodingKeys: String, CodingKey {
        case username
        case pinnedHostKeySHA256 = "pinned_hostkey_sha256"
        case localProxyPort = "local_proxy_port"
        case supportsHTTPConnectBridge = "supports_http_connect_bridge"
    }

    public init(
        username: String,
        pinnedHostKeySHA256: String,
        localProxyPort: Int = 1080,
        supportsHTTPConnectBridge: Bool = true
    ) {
        self.username = username
        self.pinnedHostKeySHA256 = pinnedHostKeySHA256
        self.localProxyPort = localProxyPort
        self.supportsHTTPConnectBridge = supportsHTTPConnectBridge
    }
}

public struct JaroPortableProfile: Codable, Identifiable, Equatable, Sendable {
    public let schemaVersion: String
    public let organization: String
    public let project: String
    public let profileId: String
    public var displayName: String
    public let tunnelProtocol: JaroTunnelProtocol
    public let host: String
    public let port: Int
    public let scope: String
    public var authorized: Bool
    public let includeDefaultRoute: Bool
    public let includedRoutes: [String]
    public let mtu: Int
    public let iosTargets: JaroIOSTargetMetadata
    public let cryptoReferences: JaroCryptoReferences
    public let wireguard: JaroWireGuardSection?
    public let sshSocks5: JaroSSHSocksSection?
    public let createdUTC: String

    public var id: String { profileId }

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case organization
        case project
        case profileId = "profile_id"
        case displayName = "display_name"
        case tunnelProtocol = "protocol"
        case host
        case port
        case scope
        case authorized
        case includeDefaultRoute = "include_default_route"
        case includedRoutes = "included_routes"
        case mtu
        case iosTargets = "ios_targets"
        case cryptoReferences = "crypto_references"
        case wireguard
        case sshSocks5 = "ssh_socks5"
        case createdUTC = "created_utc"
    }

    public init(
        schemaVersion: String = JaroConstants.schemaVersion,
        organization: String = JaroConstants.organization,
        project: String = JaroConstants.project,
        profileId: String,
        displayName: String,
        tunnelProtocol: JaroTunnelProtocol,
        host: String,
        port: Int,
        scope: String,
        authorized: Bool = false,
        includeDefaultRoute: Bool = false,
        includedRoutes: [String] = [],
        mtu: Int = 1420,
        iosTargets: JaroIOSTargetMetadata = JaroIOSTargetMetadata(),
        cryptoReferences: JaroCryptoReferences,
        wireguard: JaroWireGuardSection? = nil,
        sshSocks5: JaroSSHSocksSection? = nil,
        createdUTC: String = ISO8601DateFormatter().string(from: Date())
    ) {
        self.schemaVersion = schemaVersion
        self.organization = organization
        self.project = project
        self.profileId = profileId
        self.displayName = displayName
        self.tunnelProtocol = tunnelProtocol
        self.host = host
        self.port = port
        self.scope = scope
        self.authorized = authorized
        self.includeDefaultRoute = includeDefaultRoute
        self.includedRoutes = includedRoutes
        self.mtu = mtu
        self.iosTargets = iosTargets
        self.cryptoReferences = cryptoReferences
        self.wireguard = wireguard
        self.sshSocks5 = sshSocks5
        self.createdUTC = createdUTC
    }

    public var isLoopback: Bool {
        let normalized = host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return normalized == "localhost" || normalized == "::1" || normalized.hasPrefix("127.")
    }
}

// MARK: - App <-> NEPacketTunnelProvider IPC Messages (`sendProviderMessage` / `handleAppMessage`)

public enum JaroTunnelIPCCommand: String, Codable, Sendable {
    case statusSnapshot = "status_snapshot"
    case verifyHTTPSEgress = "verify_https_egress"
    case recentLogs = "recent_logs"
}

public struct JaroTunnelIPCRequest: Codable, Sendable {
    public let command: JaroTunnelIPCCommand
    public let probeURLString: String?

    public init(command: JaroTunnelIPCCommand, probeURLString: String? = nil) {
        self.command = command
        self.probeURLString = probeURLString
    }
}

public struct JaroTunnelIPCResponse: Codable, Sendable {
    public let state: JaroTunnelState
    public let stats: JaroTrafficStats
    public let capabilities: JaroCapabilityMatrix
    public let recentLogs: [String]
    public let lastError: String?

    public init(
        state: JaroTunnelState,
        stats: JaroTrafficStats,
        capabilities: JaroCapabilityMatrix,
        recentLogs: [String],
        lastError: String? = nil
    ) {
        self.state = state
        self.stats = stats
        self.capabilities = capabilities
        self.recentLogs = recentLogs
        self.lastError = lastError
    }
}
