// JARO WPF — Phase 6 Native iOS Tunnel Engine
// Module: JaroTunnelEngine (Native WireGuard Engine via WireGuardKit — Priority B)
// Organization: JARO COMPLEMETS

import Foundation
import JaroCore
import JaroProfiles
import JaroSecurity
#if canImport(NetworkExtension)
import NetworkExtension
#endif
#if canImport(WireGuardKit)
import WireGuardKit
#endif

public enum JaroWireGuardEngineError: Error, LocalizedError {
    case missingWireGuardProfileSection
    case invalidInterfacePrivateKey
    case invalidPeerPublicKey
    case invalidPresharedKey
    case invalidAddressCIDR(String)
    case invalidDNSServer(String)
    case unauthorizedDNSOverride
    case invalidAllowedIPRange(String)
    case invalidEndpoint(String)
    case unauthorizedGlobalRoute
    case wireGuardKitBridgeNotLinked
    case adapterNotRunning

    public var errorDescription: String? {
        switch self {
        case .missingWireGuardProfileSection:
            return "Profile does not contain a valid WireGuard configuration block"
        case .invalidInterfacePrivateKey:
            return "Invalid Curve25519 WireGuard PrivateKey retrieved from Keychain"
        case .invalidPeerPublicKey:
            return "Invalid Curve25519 WireGuard Peer PublicKey"
        case .invalidPresharedKey:
            return "Invalid 32-byte WireGuard PresharedKey retrieved from Keychain"
        case .invalidAddressCIDR(let cidr):
            return "Invalid WireGuard interface CIDR: \(cidr)"
        case .invalidDNSServer(let address):
            return "Invalid WireGuard DNS server IP address: \(address)"
        case .unauthorizedDNSOverride:
            return "WireGuard DNS override is missing explicit user authorization"
        case .invalidAllowedIPRange(let cidr):
            return "Invalid WireGuard AllowedIPs CIDR: \(cidr)"
        case .invalidEndpoint(let ep):
            return "Invalid WireGuard peer endpoint: \(ep)"
        case .unauthorizedGlobalRoute:
            return "Global default route (0.0.0.0/0 or ::/0) blocked by JARO route isolation policy"
        case .wireGuardKitBridgeNotLinked:
            return "WireGuardKit / libwg-go.a is not linked in this build. Build target WireGuardGoBridgeiOS with JARO_ENABLE_WIREGUARDKIT=1 in Xcode."
        case .adapterNotRunning:
            return "WireGuardAdapter is not currently active"
        }
    }
}

/// Native iOS WireGuard engine wrapping `WireGuardKit.WireGuardAdapter` inside `NEPacketTunnelProvider`.
public final class JaroWireGuardEngine: @unchecked Sendable {
    private let logBuffer: JaroRingLogBuffer
    #if canImport(WireGuardKit) && canImport(NetworkExtension)
    private var adapter: WireGuardAdapter?
    #endif

    public init(logBuffer: JaroRingLogBuffer) {
        self.logBuffer = logBuffer
    }

    public var isRunning: Bool {
        #if canImport(WireGuardKit) && canImport(NetworkExtension)
        return adapter != nil
        #else
        return false
        #endif
    }

    /// Parses WireGuard UAPI `get=1` key-value lines (`rx_bytes=`, `tx_bytes=`, `last_handshake_time_sec=`)
    /// returned by `WireGuardAdapter.getRuntimeConfiguration`.
    public static func parseUAPIRuntimeConfiguration(
        _ uapiText: String,
        peerPublicKeyB64: String? = nil
    ) -> JaroTrafficStats {
        var rxTotal: UInt64 = 0
        var txTotal: UInt64 = 0
        var latestHandshake: Int64?
        let expectedPeerHex: String?
        if let peerPublicKeyB64 {
            guard let keyData = Data(base64Encoded: peerPublicKeyB64), keyData.count == 32 else {
                return JaroTrafficStats()
            }
            expectedPeerHex = keyData.map { String(format: "%02x", $0) }.joined()
        } else {
            expectedPeerHex = nil
        }
        var currentPeerHex: String?
        var peerRX: UInt64 = 0
        var peerTX: UInt64 = 0
        var peerHandshake: Int64?

        func accumulatePeer() {
            guard let currentPeerHex,
                  expectedPeerHex == nil || currentPeerHex == expectedPeerHex else { return }
            rxTotal &+= peerRX
            txTotal &+= peerTX
            if let peerHandshake {
                latestHandshake = max(latestHandshake ?? peerHandshake, peerHandshake)
            }
        }

        for rawLine in uapiText.components(separatedBy: .newlines) {
            let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            guard let eq = line.firstIndex(of: "=") else { continue }
            let key = String(line[..<eq])
            let val = String(line[line.index(after: eq)...])
            switch key {
            case "public_key":
                accumulatePeer()
                currentPeerHex = val.lowercased()
                peerRX = 0
                peerTX = 0
                peerHandshake = nil
            case "rx_bytes":
                if let v = UInt64(val) { peerRX = v }
            case "tx_bytes":
                if let v = UInt64(val) { peerTX = v }
            case "last_handshake_time_sec":
                if let sec = Int64(val), sec > 0 { peerHandshake = sec }
            default:
                break
            }
        }
        accumulatePeer()
        return JaroTrafficStats(
            rxBytes: rxTotal,
            txBytes: txTotal,
            lastHandshakeEpochSec: latestHandshake
        )
    }

    #if canImport(NetworkExtension)
    public func start(
        profile: JaroPortableProfile,
        secretStore: JaroSecretStoreProtocol,
        packetTunnelProvider: NEPacketTunnelProvider
    ) async throws {
        try JaroProfileManager.validateProfile(profile)
        guard let wgSection = profile.wireguard else {
            throw JaroWireGuardEngineError.missingWireGuardProfileSection
        }

        let privateKeyB64 = try secretStore
            .loadSecretString(forURI: profile.cryptoReferences.keychainSecretRef)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard JaroCryptoValidators.isValidWireGuardKeyBase64(privateKeyB64) else {
            throw JaroWireGuardEngineError.invalidInterfacePrivateKey
        }

        var optionalPSKB64: String?
        if let pskURI = profile.cryptoReferences.keychainPskRef {
            let loaded = try secretStore
                .loadSecretString(forURI: pskURI)
                .trimmingCharacters(in: .whitespacesAndNewlines)
            guard JaroCryptoValidators.isValidWireGuardKeyBase64(loaded) else {
                throw JaroWireGuardEngineError.invalidPresharedKey
            }
            optionalPSKB64 = loaded
        }

        #if canImport(WireGuardKit)
        let tunnelConfig = try buildWireGuardKitConfiguration(
            profile: profile,
            wgSection: wgSection,
            privateKeyB64: privateKeyB64,
            presharedKeyB64: optionalPSKB64
        )

        let wgAdapter = WireGuardAdapter(with: packetTunnelProvider) { [weak self] logLevel, message in
            let levelTag: String
            switch logLevel {
            case .verbose:
                levelTag = "DEBUG"
            case .error:
                levelTag = "ERROR"
            @unknown default:
                levelTag = "INFO"
            }
            self?.logBuffer.append(level: levelTag, component: "WireGuardAdapter", message: message)
        }

        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            wgAdapter.start(tunnelConfiguration: tunnelConfig) { adapterError in
                if let adapterError = adapterError {
                    continuation.resume(throwing: adapterError)
                } else {
                    continuation.resume(returning: ())
                }
            }
        }
        self.adapter = wgAdapter
        logBuffer.append(
            level: "INFO",
            component: "JaroWireGuardEngine",
            message: "WireGuardAdapter started for profile \(profile.profileId) (\(profile.host):\(profile.port))"
        )
        #else
        _ = (wgSection, optionalPSKB64, packetTunnelProvider)
        logBuffer.append(
            level: "ERROR",
            component: "JaroWireGuardEngine",
            message: "WireGuardKit binary bridge not linked in current target"
        )
        throw JaroWireGuardEngineError.wireGuardKitBridgeNotLinked
        #endif
    }

    /// Re-applies tunnel configuration during Wi-Fi <-> Cellular roaming without tearing down `utun`.
    public func handleNetworkChange(
        profile: JaroPortableProfile,
        secretStore: JaroSecretStoreProtocol
    ) async throws {
        #if canImport(WireGuardKit)
        guard let wgAdapter = self.adapter else {
            throw JaroWireGuardEngineError.adapterNotRunning
        }
        guard let wgSection = profile.wireguard else {
            throw JaroWireGuardEngineError.missingWireGuardProfileSection
        }
        let privateKeyB64 = try secretStore
            .loadSecretString(forURI: profile.cryptoReferences.keychainSecretRef)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let optionalPSKB64 = try profile.cryptoReferences.keychainPskRef.map {
            try secretStore.loadSecretString(forURI: $0).trimmingCharacters(in: .whitespacesAndNewlines)
        }
        let updatedConfig = try buildWireGuardKitConfiguration(
            profile: profile,
            wgSection: wgSection,
            privateKeyB64: privateKeyB64,
            presharedKeyB64: optionalPSKB64
        )
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            wgAdapter.update(tunnelConfiguration: updatedConfig) { adapterError in
                if let adapterError = adapterError {
                    continuation.resume(throwing: adapterError)
                } else {
                    continuation.resume(returning: ())
                }
            }
        }
        logBuffer.append(level: "INFO", component: "JaroWireGuardEngine", message: "WireGuardAdapter roaming update applied")
        #else
        _ = (profile, secretStore)
        throw JaroWireGuardEngineError.wireGuardKitBridgeNotLinked
        #endif
    }

    public func stop() async throws {
        #if canImport(WireGuardKit)
        guard let wgAdapter = self.adapter else { return }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            wgAdapter.stop { adapterError in
                if let adapterError = adapterError {
                    continuation.resume(throwing: adapterError)
                } else {
                    continuation.resume(returning: ())
                }
            }
        }
        self.adapter = nil
        logBuffer.append(level: "INFO", component: "JaroWireGuardEngine", message: "WireGuardAdapter stopped cleanly")
        #endif
    }

    public func fetchRuntimeStats(peerPublicKeyB64: String? = nil) async -> JaroTrafficStats {
        #if canImport(WireGuardKit)
        guard let wgAdapter = self.adapter else { return JaroTrafficStats() }
        return await withCheckedContinuation { continuation in
            wgAdapter.getRuntimeConfiguration { settingsString in
                guard let uapi = settingsString else {
                    continuation.resume(returning: JaroTrafficStats())
                    return
                }
                continuation.resume(returning: Self.parseUAPIRuntimeConfiguration(uapi, peerPublicKeyB64: peerPublicKeyB64))
            }
        }
        #else
        return JaroTrafficStats()
        #endif
    }
    #endif

    #if canImport(WireGuardKit)
    private func buildWireGuardKitConfiguration(
        profile: JaroPortableProfile,
        wgSection: JaroWireGuardSection,
        privateKeyB64: String,
        presharedKeyB64: String?
    ) throws -> TunnelConfiguration {
        guard let privateKey = PrivateKey(base64Key: privateKeyB64) else {
            throw JaroWireGuardEngineError.invalidInterfacePrivateKey
        }
        guard let peerPublicKey = PublicKey(base64Key: wgSection.peerPublicKeyB64) else {
            throw JaroWireGuardEngineError.invalidPeerPublicKey
        }
        let addressCIDRs = (wgSection.tunnelAddressesCIDR?.isEmpty == false)
            ? (wgSection.tunnelAddressesCIDR ?? [])
            : [wgSection.tunnelAddressCIDR]
        let interfaceRanges = try addressCIDRs.map { cidr -> IPAddressRange in
            guard let range = IPAddressRange(from: cidr) else {
                throw JaroWireGuardEngineError.invalidAddressCIDR(cidr)
            }
            return range
        }
        let formattedEndpoint = profile.host.contains(":")
            ? "[\(profile.host)]:\(profile.port)"
            : "\(profile.host):\(profile.port)"
        guard let endpoint = Endpoint(from: formattedEndpoint) else {
            throw JaroWireGuardEngineError.invalidEndpoint(formattedEndpoint)
        }

        var interfaceConfig = InterfaceConfiguration(privateKey: privateKey)
        interfaceConfig.addresses = interfaceRanges
        interfaceConfig.mtu = UInt16(profile.mtu)
        let dnsAddresses = wgSection.dnsServers ?? []
        if !dnsAddresses.isEmpty && wgSection.dnsOverrideAuthorized != true {
            throw JaroWireGuardEngineError.unauthorizedDNSOverride
        }
        interfaceConfig.dns = try dnsAddresses.map { address -> DNSServer in
            guard let server = DNSServer(from: address) else {
                throw JaroWireGuardEngineError.invalidDNSServer(address)
            }
            return server
        }

        var peerConfig = PeerConfiguration(publicKey: peerPublicKey)
        peerConfig.endpoint = endpoint
        if let pskRaw = presharedKeyB64 {
            guard let psk = PreSharedKey(base64Key: pskRaw) else {
                throw JaroWireGuardEngineError.invalidPresharedKey
            }
            peerConfig.preSharedKey = psk
        }
        if let keepalive = wgSection.persistentKeepaliveSec, keepalive > 0 {
            peerConfig.persistentKeepAlive = UInt16(min(keepalive, 65535))
        }

        var allowedRanges: [IPAddressRange] = []
        for rawCIDR in profile.includedRoutes {
            if (rawCIDR == "0.0.0.0/0" || rawCIDR == "::/0") && !profile.includeDefaultRoute {
                throw JaroWireGuardEngineError.unauthorizedGlobalRoute
            }
            guard let parsedRange = IPAddressRange(from: rawCIDR) else {
                throw JaroWireGuardEngineError.invalidAllowedIPRange(rawCIDR)
            }
            allowedRanges.append(parsedRange)
        }
        peerConfig.allowedIPs = allowedRanges

        return TunnelConfiguration(
            name: profile.displayName,
            interface: interfaceConfig,
            peers: [peerConfig]
        )
    }
    #endif
}
