// JARO WPF — Phase 6 Native iOS Tunnel Engine
// Module: JaroPacketTunnel (`NEPacketTunnelProvider` VPN System Extension)
// Organization: JARO COMPLEMETS
//
// HONESTY NOTICE:
// This VPN extension is architected for iOS 16.0+ (`<= 15 MB` jetsam RAM ceiling) and uses only
// Apple-sanctioned frameworks (`NetworkExtension`, `Security`, `Network`, `SwiftNIO SSH`, `WireGuardKit`).
// However, it remains `UNVERIFIED_ON_PHYSICAL_IPHONE` until compiled in Xcode on macOS, signed with
// `com.apple.developer.networking.networkextension` (`packet-tunnel-provider`), and tested on a real iPhone.

import Foundation
import JaroCore
import JaroDiagnostics
import JaroProfiles
import JaroSecurity
import JaroTunnelEngine
#if canImport(NetworkExtension)
import NetworkExtension
#endif
#if canImport(Darwin)
import Darwin
#endif

#if canImport(NetworkExtension)
public final class PacketTunnelProvider: NEPacketTunnelProvider {
    /// Minimum free memory headroom (3.5 MB) kept inside iOS's strict 15 MB NetworkExtension jetsam limit.
    private static let minimumHeadroomBytes: UInt64 = 3_500_000

    private let stateLock = NSLock()
    private let logBuffer = JaroRingLogBuffer(maxEntries: 160, maxEntryBytes: 384)
    private let secretStore = JaroKeychainVault()
    private let backoff = JaroExponentialBackoff(
        baseDelaySeconds: 1.0,
        maxDelaySeconds: 30.0,
        multiplier: 2.0,
        jitterRatio: 0.15,
        maxConsecutiveFailures: 5,
        cooldownSeconds: 60.0
    )
    private let httpsDiagnostic = JaroHTTPSEgressDiagnostic(maxProbeBytes: 6144)

    private lazy var wireGuardEngine = JaroWireGuardEngine(logBuffer: logBuffer)
    private lazy var sshEngine = JaroNativeSSHEngine(logBuffer: logBuffer)
    private lazy var localSOCKS5Server = JaroLocalSOCKS5Server(sshEngine: sshEngine, logBuffer: logBuffer)
    private lazy var pathCostMonitor = JaroPathCostMonitor(allowExpensivePaths: false, logBuffer: logBuffer)

    private var activeProfile: JaroPortableProfile?
    private var currentState: JaroTunnelState = .disconnected
    private var capabilities = JaroCapabilityMatrix()
    private var lastErrorMessage: String?
    private var reconnectTask: Task<Void, Never>?

    // MARK: - NEPacketTunnelProvider Lifecycle

    public override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        logBuffer.append(level: "INFO", component: "PacketTunnelProvider", message: "Starting JARO PacketTunnel extension")

        // 1. Check extension memory headroom (`< 15 MB` ceiling)
        if let avail = Self.queryAvailableExtensionMemoryBytes(), avail < Self.minimumHeadroomBytes {
            let err = NSError(
                domain: "com.jarocomplements.jarowpf.PacketTunnel",
                code: 1001,
                userInfo: [NSLocalizedDescriptionKey: "Insufficient NetworkExtension memory headroom (\(avail) bytes free)"]
            )
            transitionState(.failed, error: err.localizedDescription)
            completionHandler(err)
            return
        }

        // 2. Decode `.jaroprofile` v1.0 from `NETunnelProviderProtocol.providerConfiguration`
        guard let tunnelProto = self.protocolConfiguration as? NETunnelProviderProtocol,
              let providerConfig = tunnelProto.providerConfiguration,
              let profileJSONString = providerConfig["jaro_profile_json"] as? String,
              let profileData = profileJSONString.data(using: .utf8) else {
            let err = NSError(
                domain: "com.jarocomplements.jarowpf.PacketTunnel",
                code: 1002,
                userInfo: [NSLocalizedDescriptionKey: "Missing jaro_profile_json in providerConfiguration"]
            )
            transitionState(.remoteServerRequired, error: err.localizedDescription)
            completionHandler(err)
            return
        }

        let allowExpensive = (providerConfig["allow_expensive_paths"] as? Bool) ?? false
        let userMetered = providerConfig["user_marked_metered"] as? Bool
        pathCostMonitor.updateCostPolicy(
            allowExpensivePaths: allowExpensive,
            userMarkedMeteredOverride: userMetered
        )

        let profileManager = JaroProfileManager(secretStore: secretStore)
        let profile: JaroPortableProfile
        do {
            profile = try profileManager.importPortableJSON(profileData, persist: false)
            guard profile.authorized else {
                throw JaroProfileValidationError.invalidProfileIdentifier(
                    "Profile '\(profile.profileId)' is not marked authorized=true"
                )
            }
        } catch {
            transitionState(.failed, error: error.localizedDescription)
            completionHandler(error)
            return
        }

        stateLock.lock()
        self.activeProfile = profile
        stateLock.unlock()
        transitionState(.connecting, error: nil)

        Task {
            do {
                try await bringUpTunnel(for: profile)
                startNetworkPathObserver(for: profile)
                backoff.recordSuccess()
                completionHandler(nil)
            } catch {
                transitionState(.failed, error: error.localizedDescription)
                completionHandler(error)
            }
        }
    }

    public override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        logBuffer.append(
            level: "INFO",
            component: "PacketTunnelProvider",
            message: "Stopping JARO PacketTunnel (reason=\(reason.rawValue))"
        )
        reconnectTask?.cancel()
        reconnectTask = nil
        pathCostMonitor.stop()

        Task {
            try? await localSOCKS5Server.stop()
            try? await sshEngine.disconnect()
            try? await wireGuardEngine.stop()
            stateLock.lock()
            self.activeProfile = nil
            self.capabilities = JaroCapabilityMatrix()
            stateLock.unlock()
            self.transitionState(.disconnected, error: nil)
            completionHandler()
        }
    }

    public override func handleAppMessage(
        _ messageData: Data,
        completionHandler: ((Data?) -> Void)?
    ) {
        guard let completionHandler = completionHandler else { return }
        guard let req = try? JSONDecoder().decode(JaroTunnelIPCRequest.self, from: messageData) else {
            completionHandler(nil)
            return
        }

        Task {
            switch req.command {
            case .statusSnapshot, .recentLogs:
                let resp = await buildIPCResponse()
                completionHandler(try? JSONEncoder().encode(resp))

            case .verifyHTTPSEgress:
                if let urlStr = req.probeURLString, let url = URL(string: urlStr) {
                    await runLiveHTTPSVerification(probeURL: url)
                }
                let resp = await buildIPCResponse()
                completionHandler(try? JSONEncoder().encode(resp))
            }
        }
    }

    // MARK: - Protocol Bring-Up & Split-Tunnel Enforcement

    private func bringUpTunnel(for profile: JaroPortableProfile) async throws {
        switch profile.tunnelProtocol {
        case .wireguard:
            try await wireGuardEngine.start(
                profile: profile,
                secretStore: secretStore,
                packetTunnelProvider: self
            )
            let wgStats = await wireGuardEngine.fetchRuntimeStats()
            stateLock.lock()
            capabilities.wireguardHandshake = (wgStats.lastHandshakeEpochSec ?? 0) > 0
            capabilities.wireguardBidirectionalTransfer = wgStats.hasBidirectionalTransfer
            stateLock.unlock()
            transitionState(.connectedHandshakeOnly, error: nil)

        case .sshSocks5:
            guard let sshSection = profile.sshSocks5 else {
                throw JaroSSHEngineError.missingSSHProfileSection
            }
            try await sshEngine.connect(profile: profile, secretStore: secretStore)
            let boundPort = try await localSOCKS5Server.start(
                bindHost: "127.0.0.1",
                port: sshSection.localProxyPort
            )

            let netSettings = try buildSSHProxyNetworkSettings(profile: profile, localProxyPort: boundPort)
            try await setTunnelNetworkSettings(netSettings)

            stateLock.lock()
            capabilities.sshAuthenticatedSession = sshEngine.isSessionActive
            capabilities.localProxyListening = localSOCKS5Server.isListening
            stateLock.unlock()
            transitionState(.connectedHandshakeOnly, error: nil)
        }
    }

    private func buildSSHProxyNetworkSettings(
        profile: JaroPortableProfile,
        localProxyPort: Int
    ) throws -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: profile.host)
        settings.mtu = NSNumber(value: profile.mtu)

        // Isolated loopback-style tunnel interface so global IP routing is NEVER hijacked when includeDefaultRoute == false
        let ipv4 = NEIPv4Settings(addresses: ["198.18.0.2"], subnetMasks: ["255.255.255.252"])
        var neRoutes: [NEIPv4Route] = []
        for cidr in profile.includedRoutes {
            if (cidr == "0.0.0.0/0" || cidr == "::/0") && !profile.includeDefaultRoute {
                throw JaroProfileValidationError.unauthorizedGlobalDefaultRoute(cidr)
            }
            if cidr == "0.0.0.0/0" && profile.includeDefaultRoute {
                neRoutes.append(.default())
            } else if let route = Self.parseIPv4CIDRToNERoute(cidr) {
                neRoutes.append(route)
            }
        }
        ipv4.includedRoutes = neRoutes
        settings.ipv4Settings = ipv4

        // Configure NEProxySettings pointing to our dual SOCKS5 + HTTP CONNECT listener on 127.0.0.1:<port>
        let proxy = NEProxySettings()
        let proxyServer = NEProxyServer(address: "127.0.0.1", port: localProxyPort)
        proxy.httpEnabled = true
        proxy.httpServer = proxyServer
        proxy.httpsEnabled = true
        proxy.httpsServer = proxyServer
        proxy.excludeSimpleHostnames = true
        proxy.exceptionList = ["127.0.0.1", "localhost", "::1"]
        settings.proxySettings = proxy

        return settings
    }

    // MARK: - Live HTTPS Egress Verification & Automatic Recovery

    private func runLiveHTTPSVerification(probeURL: URL) async {
        stateLock.lock()
        let prof = activeProfile
        stateLock.unlock()
        guard let profile = prof else { return }

        let proxyPort = (profile.tunnelProtocol == .sshSocks5) ? localSOCKS5Server.boundPort : nil
        let result = await httpsDiagnostic.verifyHTTPSEgress(
            url: probeURL,
            expectedStatus: 200,
            localHTTPConnectProxyPort: proxyPort
        )

        stateLock.lock()
        capabilities.captivePortalDetected = result.captivePortalSuspected
        if profile.tunnelProtocol == .sshSocks5 {
            capabilities.sshAuthenticatedSession = sshEngine.isSessionActive
            capabilities.localProxyListening = localSOCKS5Server.isListening
            capabilities.sshVerifiedHTTPS = result.httpsVerified
        } else {
            capabilities.wireguardVerifiedHTTPS = result.httpsVerified
        }
        stateLock.unlock()

        if result.httpsVerified {
            transitionState(.connectedVerifiedHTTPS, error: nil)
        } else if let err = result.errorDescription {
            logBuffer.append(level: "WARN", component: "PacketTunnelProvider", message: "HTTPS probe failed: \(err)")
        }
    }

    private func startNetworkPathObserver(for profile: JaroPortableProfile) {
        pathCostMonitor.start { [weak self] costSnapshot, pathSatisfied in
            guard let self = self else { return }
            if !costSnapshot.satisfiesTunnelPolicy {
                self.transitionState(
                    .blockedByCostPolicy,
                    error: "Active path (\(costSnapshot.interfaceKind)) is metered/expensive and blocked by JARO cost policy"
                )
                return
            }
            guard pathSatisfied else { return }
            self.scheduleControlledRecovery(for: profile)
        }
    }

    private func scheduleControlledRecovery(for profile: JaroPortableProfile) {
        reconnectTask?.cancel()
        reconnectTask = Task { [weak self] in
            guard let self = self else { return }
            switch profile.tunnelProtocol {
            case .wireguard:
                try? await self.wireGuardEngine.handleNetworkChange(profile: profile, secretStore: self.secretStore)
            case .sshSocks5:
                if self.sshEngine.isSessionActive && self.localSOCKS5Server.isListening {
                    return
                }
                guard let delay = self.backoff.recordFailureAndNextDelay() else {
                    self.transitionState(
                        .circuitBreakerOpen,
                        error: "Circuit breaker open after repeated SSH reconnect failures"
                    )
                    return
                }
                self.transitionState(.reconnecting, error: nil)
                try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
                guard !Task.isCancelled else { return }
                do {
                    try await self.bringUpTunnel(for: profile)
                    self.backoff.recordSuccess()
                } catch {
                    self.transitionState(.failed, error: error.localizedDescription)
                }
            }
        }
    }

    // MARK: - Helpers & Telemetry

    private func buildIPCResponse() async -> JaroTunnelIPCResponse {
        stateLock.lock()
        let prof = activeProfile
        let st = currentState
        var caps = capabilities
        let err = lastErrorMessage
        stateLock.unlock()

        var stats: JaroTrafficStats
        if prof?.tunnelProtocol == .wireguard {
            stats = await wireGuardEngine.fetchRuntimeStats()
            caps.wireguardHandshake = (stats.lastHandshakeEpochSec ?? 0) > 0
            caps.wireguardBidirectionalTransfer = stats.hasBidirectionalTransfer
        } else {
            stats = localSOCKS5Server.trafficAccumulator.snapshot()
            caps.sshAuthenticatedSession = sshEngine.isSessionActive
            caps.localProxyListening = localSOCKS5Server.isListening
        }
        stats.availableExtensionMemoryBytes = Self.queryAvailableExtensionMemoryBytes()

        return JaroTunnelIPCResponse(
            state: st,
            stats: stats,
            capabilities: caps,
            recentLogs: logBuffer.snapshot(limit: 40),
            lastError: err
        )
    }

    private func transitionState(_ newState: JaroTunnelState, error: String?) {
        let sanitized = error.map(JaroSecretRedactor.redact)
        stateLock.lock()
        currentState = newState
        lastErrorMessage = sanitized
        stateLock.unlock()
        if let msg = sanitized {
            logBuffer.append(level: "WARN", component: "State", message: "\(newState.rawValue): \(msg)")
        } else {
            logBuffer.append(level: "INFO", component: "State", message: "Transition -> \(newState.rawValue)")
        }
    }

    private static func parseIPv4CIDRToNERoute(_ cidr: String) -> NEIPv4Route? {
        let parts = cidr.split(separator: "/")
        guard parts.count == 2, let prefix = Int(parts[1]), (1...32).contains(prefix) else { return nil }
        let maskBits: UInt32 = prefix == 0 ? 0 : (~UInt32(0) << (32 - prefix))
        let m1 = (maskBits >> 24) & 0xFF
        let m2 = (maskBits >> 16) & 0xFF
        let m3 = (maskBits >> 8) & 0xFF
        let m4 = maskBits & 0xFF
        return NEIPv4Route(destinationAddress: String(parts[0]), subnetMask: "\(m1).\(m2).\(m3).\(m4)")
    }

    private static func queryAvailableExtensionMemoryBytes() -> UInt64? {
        #if os(iOS)
        return UInt64(os_proc_available_memory())
        #else
        return nil
        #endif
    }
}
#endif
