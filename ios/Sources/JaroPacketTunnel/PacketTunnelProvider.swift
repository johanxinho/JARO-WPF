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
#if canImport(Network)
import Network
#endif
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
    private let dnsDiagnostic = JaroDNSResolutionDiagnostic()
    private var lastUnderlyingNetwork: JaroClassifierResult?

    private lazy var wireGuardEngine = JaroWireGuardEngine(logBuffer: logBuffer)
    private lazy var sshEngine = JaroNativeSSHEngine(logBuffer: logBuffer)
    private lazy var localSOCKS5Server = JaroLocalSOCKS5Server(sshEngine: sshEngine, logBuffer: logBuffer)
    private lazy var pathCostMonitor = JaroPathCostMonitor(allowExpensivePaths: false, logBuffer: logBuffer)

    private var activeProfile: JaroPortableProfile?
    private var currentState: JaroTunnelState = .disconnected
    private var capabilities = JaroCapabilityMatrix()
    private var lastErrorMessage: String?
    private var startTask: Task<Void, Never>?
    private var reconnectTask: Task<Void, Never>?
    private var pathSuspensionTask: Task<Void, Never>?
    private var isStopping = false
    private var hasObservedInitialNetworkPath = false

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
            profile = try profileManager.importPortableJSON(
                profileData,
                persist: false,
                allowGlobalRoutes: (providerConfig["allow_global_routes"] as? Bool) == true,
                allowDNSOverride: (providerConfig["allow_dns_override"] as? Bool) == true
            )
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
        self.isStopping = false
        self.hasObservedInitialNetworkPath = false
        stateLock.unlock()
        transitionState(.connecting, error: nil)

        let task = Task { [weak self] in
            guard let self = self else {
                completionHandler(CancellationError())
                return
            }
            do {
                try await self.bringUpTunnel(for: profile)
                try Task.checkCancellation()
                self.stateLock.lock()
                let stopping = self.isStopping
                self.stateLock.unlock()
                guard !stopping else { throw CancellationError() }
                self.startNetworkPathObserver(for: profile)
                self.backoff.recordSuccess()
                completionHandler(nil)
            } catch {
                await self.stopTransportsAndClearNetworkSettings()
                if !(error is CancellationError) {
                    self.transitionState(.failed, error: error.localizedDescription)
                }
                completionHandler(error)
            }
            self.stateLock.lock()
            self.startTask = nil
            self.stateLock.unlock()
        }
        stateLock.lock()
        self.startTask = task
        stateLock.unlock()
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
        stateLock.lock()
        isStopping = true
        let pendingStart = startTask
        let pendingReconnect = reconnectTask
        startTask = nil
        reconnectTask = nil
        pathSuspensionTask = nil
        stateLock.unlock()
        pendingStart?.cancel()
        pendingReconnect?.cancel()
        pathCostMonitor.stop()

        Task { [weak self] in
            guard let self = self else {
                completionHandler()
                return
            }
            if let pendingStart = pendingStart { await pendingStart.value }
            if let pendingReconnect = pendingReconnect { await pendingReconnect.value }
            await self.stopTransportsAndClearNetworkSettings()
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

            case .verifyDNSResolution:
                if let queryName = req.dnsQueryName {
                    await runDNSResolutionVerification(queryName: queryName)
                }
                let resp = await buildIPCResponse()
                completionHandler(try? JSONEncoder().encode(resp))

            case .verifyUnderlyingNetwork:
                await runUnderlyingNetworkClassification(
                    dnsQueryName: req.dnsQueryName,
                    httpsURLString: req.probeURLString
                )
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
            let wgStats = await wireGuardEngine.fetchRuntimeStats(peerPublicKeyB64: profile.wireguard?.peerPublicKeyB64)
            stateLock.lock()
            capabilities.wireguardHandshake = wgStats.hasFreshHandshake
            capabilities.wireguardBidirectionalTransfer = false
            capabilities.wireguardDNSConfigured = !(profile.wireguard?.dnsServers ?? []).isEmpty
            stateLock.unlock()
            transitionState(
                wgStats.hasFreshHandshake ? .connectedHandshakeOnly : .unverified,
                error: wgStats.hasFreshHandshake ? nil : "WireGuard adapter started; no fresh handshake from the configured peer has been observed"
            )

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
            capabilities.sshAuthenticatedSession = sshEngine.isSSHAuthenticated
            capabilities.localProxyListening = localSOCKS5Server.isListening
            stateLock.unlock()
            transitionState(
                sshEngine.isSSHAuthenticated ? .connectedHandshakeOnly : .unverified,
                error: sshEngine.isSSHAuthenticated ? nil : "SSH TCP transport and proxy are ready; SSH authentication is not yet verified"
            )
        }
    }

    private func buildSSHProxyNetworkSettings(
        profile: JaroPortableProfile,
        localProxyPort: Int
    ) throws -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: profile.host)
        settings.mtu = NSNumber(value: profile.mtu)

        // This SSH mode is an HTTP/SOCKS proxy, not an IP packet forwarder. The provider
        // does not consume packetFlow, so installing any included IP routes would blackhole traffic.
        guard profile.includedRoutes.isEmpty && !profile.includeDefaultRoute else {
            throw JaroProfileValidationError.invalidProfileIdentifier(
                "SSH/SOCKS5 mode cannot install IP routes until packetFlow forwarding is implemented"
            )
        }
        let ipv4 = NEIPv4Settings(addresses: ["198.18.0.2"], subnetMasks: ["255.255.255.252"])
        ipv4.includedRoutes = []
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

        let beforeStats: JaroTrafficStats?
        if profile.tunnelProtocol == .wireguard {
            guard let wg = profile.wireguard,
                  let host = probeURL.host,
                  Self.addressIsCovered(host, by: profile.includedRoutes) else {
                stateLock.lock()
                capabilities.wireguardVerifiedHTTPS = false
                stateLock.unlock()
                transitionState(.unverified, error: "WireGuard HTTPS probe must use an IP literal covered by this peer's AllowedIPs")
                return
            }
            beforeStats = await wireGuardEngine.fetchRuntimeStats(peerPublicKeyB64: wg.peerPublicKeyB64)
        } else {
            beforeStats = nil
        }

        let proxyPort = (profile.tunnelProtocol == .sshSocks5) ? localSOCKS5Server.boundPort : nil
        let result = await httpsDiagnostic.verifyHTTPSEgress(
            url: probeURL,
            expectedStatus: 200,
            localHTTPConnectProxyPort: proxyPort
        )
        let afterStats: JaroTrafficStats?
        if profile.tunnelProtocol == .wireguard {
            afterStats = await wireGuardEngine.fetchRuntimeStats(peerPublicKeyB64: profile.wireguard?.peerPublicKeyB64)
        } else {
            afterStats = nil
        }

        stateLock.lock()
        capabilities.captivePortalDetected = result.captivePortalSuspected
        if profile.tunnelProtocol == .sshSocks5 {
            capabilities.sshAuthenticatedSession = sshEngine.isSSHAuthenticated
            capabilities.localProxyListening = localSOCKS5Server.isListening
            capabilities.sshVerifiedHTTPS = result.httpsVerified
        } else {
            let rxAfter = afterStats?.rxBytes ?? 0
            let rxBefore = beforeStats?.rxBytes ?? 0
            let txAfter = afterStats?.txBytes ?? 0
            let txBefore = beforeStats?.txBytes ?? 0
            let rxDelta = rxAfter >= rxBefore ? rxAfter - rxBefore : 0
            let txDelta = txAfter >= txBefore ? txAfter - txBefore : 0
            capabilities.wireguardHandshake = afterStats?.hasFreshHandshake == true
            capabilities.wireguardRXDeltaBytes = rxDelta
            capabilities.wireguardTXDeltaBytes = txDelta
            capabilities.wireguardBidirectionalTransfer = rxDelta > 0 && txDelta > 0
            capabilities.wireguardVerifiedHTTPS = result.httpsVerified &&
                afterStats?.hasFreshHandshake == true && rxDelta > 0 && txDelta > 0
        }
        let wgVerified = capabilities.wireguardVerifiedHTTPS
        let wgHandshake = capabilities.wireguardHandshake
        stateLock.unlock()

        if profile.tunnelProtocol == .wireguard {
            if wgVerified {
                transitionState(.connectedVerifiedHTTPS, error: nil)
            } else if wgHandshake {
                transitionState(.connectedHandshakeOnly, error: "HTTPS response, fresh peer handshake, and bidirectional peer-counter deltas are all required for verification")
            } else {
                transitionState(.unverified, error: result.errorDescription ?? "No fresh handshake and bidirectional data evidence from the selected WireGuard peer")
            }
        } else if result.httpsVerified {
            transitionState(.connectedVerifiedHTTPS, error: nil)
        } else if let err = result.errorDescription {
            logBuffer.append(level: "WARN", component: "PacketTunnelProvider", message: "HTTPS probe failed: \(err)")
        }
    }

    private func runDNSResolutionVerification(queryName: String) async {
        stateLock.lock()
        let profile = activeProfile
        stateLock.unlock()
        guard let profile, profile.tunnelProtocol == .wireguard,
              let wg = profile.wireguard,
              wg.dnsOverrideAuthorized == true,
              let servers = wg.dnsServers, !servers.isEmpty else {
            stateLock.lock()
            capabilities.wireguardDNSConfigured = false
            capabilities.wireguardDNSResolutionVerified = false
            stateLock.unlock()
            transitionState(.unverified, error: "DNS verification requires an authorized WireGuard DNS server in the active profile")
            return
        }
        guard servers.allSatisfy({ Self.addressIsCovered($0, by: profile.includedRoutes) }) else {
            stateLock.lock()
            capabilities.wireguardDNSResolutionVerified = false
            stateLock.unlock()
            transitionState(.unverified, error: "At least one configured DNS server is outside AllowedIPs; refusing a possible physical-path DNS query")
            return
        }
        let before = await wireGuardEngine.fetchRuntimeStats(peerPublicKeyB64: wg.peerPublicKeyB64)
        let result = await dnsDiagnostic.resolve(queryName: queryName, configuredServers: servers)
        let after = await wireGuardEngine.fetchRuntimeStats(peerPublicKeyB64: wg.peerPublicKeyB64)
        let rxDelta = after.rxBytes >= before.rxBytes ? after.rxBytes - before.rxBytes : 0
        let txDelta = after.txBytes >= before.txBytes ? after.txBytes - before.txBytes : 0
        let dnsEvidence = result.succeeded && after.hasFreshHandshake && rxDelta > 0 && txDelta > 0
        stateLock.lock()
        capabilities.wireguardDNSConfigured = true
        capabilities.wireguardDNSResolutionVerified = dnsEvidence
        capabilities.wireguardHandshake = after.hasFreshHandshake
        capabilities.wireguardRXDeltaBytes = rxDelta
        capabilities.wireguardTXDeltaBytes = txDelta
        capabilities.wireguardBidirectionalTransfer = rxDelta > 0 && txDelta > 0
        stateLock.unlock()
        if !dnsEvidence {
            let reason = result.errorDescription ?? "System resolver returned/cached a result without fresh bidirectional peer-counter evidence"
            transitionState(after.hasFreshHandshake ? .connectedHandshakeOnly : .unverified, error: reason)
        } else {
            transitionState(.connectedHandshakeOnly, error: nil)
            logBuffer.append(level: "INFO", component: "DNS diagnostic", message: "System resolver returned a result and the configured peer counters changed RX/TX; this does not prove absence of DNS leaks")
        }
    }

    private static func addressIsCovered(_ address: String, by routes: [String]) -> Bool {
        guard let target = addressBytes(address) else { return false }
        for route in routes {
            let parts = route.split(separator: "/")
            guard parts.count == 2, let prefix = Int(parts[1]),
                  let network = addressBytes(String(parts[0])),
                  network.family == target.family, (0...target.bytes.count * 8).contains(prefix) else { continue }
            var matches = true
            for index in target.bytes.indices {
                let bits = min(8, max(0, prefix - index * 8))
                let mask: UInt8 = bits == 0 ? 0 : UInt8.max << (8 - bits)
                if (target.bytes[index] & mask) != (network.bytes[index] & mask) {
                    matches = false
                    break
                }
            }
            if matches { return true }
        }
        return false
    }

    private static func addressBytes(_ address: String) -> (family: Int, bytes: [UInt8])? {
        if let ipv4 = IPv4Address(address) { return (4, Array(ipv4.rawValue)) }
        if let ipv6 = IPv6Address(address) { return (6, Array(ipv6.rawValue)) }
        return nil
    }

    private func startNetworkPathObserver(for profile: JaroPortableProfile) {
        pathCostMonitor.start { [weak self] costSnapshot, pathSatisfied in
            guard let self = self else { return }
            self.stateLock.lock()
            let stopping = self.isStopping
            let isInitialObservation = !self.hasObservedInitialNetworkPath
            self.hasObservedInitialNetworkPath = true
            self.stateLock.unlock()
            guard !stopping else { return }

            if !costSnapshot.satisfiesTunnelPolicy {
                self.blockTunnelForCostPolicy(interfaceKind: costSnapshot.interfaceKind)
                return
            }

            guard pathSatisfied else {
                self.suspendTunnelForUnsatisfiedPath()
                return
            }
            // NWPathMonitor reports the current path once after start; only later updates are roaming/recovery events.
            guard !isInitialObservation else { return }
            self.scheduleControlledRecovery(for: profile)
        }
    }

    private func blockTunnelForCostPolicy(interfaceKind: String) {
        stateLock.lock()
        let pendingReconnect = reconnectTask
        reconnectTask = nil
        let alreadyBlocked = currentState == .blockedByCostPolicy
        capabilities = JaroCapabilityMatrix()
        let stopping = isStopping
        stateLock.unlock()
        pendingReconnect?.cancel()
        guard !alreadyBlocked, !stopping else { return }

        transitionState(
            .blockedByCostPolicy,
            error: "Active path (\(interfaceKind)) is metered/expensive and blocked by JARO cost policy"
        )
        Task { [weak self] in
            guard let self = self else { return }
            await self.stopTransportsAndClearNetworkSettings()
        }
    }

    private func suspendTunnelForUnsatisfiedPath() {
        stateLock.lock()
        guard !isStopping else {
            stateLock.unlock()
            return
        }
        let pendingReconnect = reconnectTask
        reconnectTask = nil
        let alreadySuspended = pathSuspensionTask != nil
        capabilities = JaroCapabilityMatrix()
        stateLock.unlock()
        pendingReconnect?.cancel()
        transitionState(.reconnecting, error: "Network path is not satisfied; tunnel settings are being removed and traffic is unverified")
        guard !alreadySuspended else { return }

        let task = Task { [weak self] in
            guard let self = self else { return }
            await self.stopTransportsAndClearNetworkSettings()
        }
        stateLock.lock()
        pathSuspensionTask = task
        stateLock.unlock()
    }

    private func scheduleControlledRecovery(for profile: JaroPortableProfile) {
        stateLock.lock()
        guard !isStopping else {
            stateLock.unlock()
            return
        }
        let previousRecovery = reconnectTask
        reconnectTask = nil
        let suspension = pathSuspensionTask
        pathSuspensionTask = nil
        capabilities = JaroCapabilityMatrix()
        stateLock.unlock()
        previousRecovery?.cancel()

        let task = Task { [weak self] in
            guard let self = self else { return }
            if let suspension = suspension { await suspension.value }
            self.stateLock.lock()
            let stopping = self.isStopping
            self.stateLock.unlock()
            guard !stopping, !Task.isCancelled else { return }
            guard let delay = self.backoff.recordFailureAndNextDelay() else {
                self.transitionState(
                    .circuitBreakerOpen,
                    error: "Circuit breaker open after repeated tunnel recovery failures"
                )
                return
            }
            self.transitionState(.reconnecting, error: nil)
            do {
                try await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
            } catch {
                return
            }
            guard !Task.isCancelled else { return }
            do {
                switch profile.tunnelProtocol {
                case .wireguard:
                    if self.wireGuardEngine.isRunning {
                        try await self.wireGuardEngine.handleNetworkChange(profile: profile, secretStore: self.secretStore)
                    } else {
                        try await self.wireGuardEngine.start(
                            profile: profile,
                            secretStore: self.secretStore,
                            packetTunnelProvider: self
                        )
                    }
                    let stats = await self.wireGuardEngine.fetchRuntimeStats(peerPublicKeyB64: profile.wireguard?.peerPublicKeyB64)
                    self.stateLock.lock()
                    self.capabilities.wireguardHandshake = stats.hasFreshHandshake
                    self.capabilities.wireguardBidirectionalTransfer = false
                    self.stateLock.unlock()
                    if stats.hasFreshHandshake {
                        self.backoff.recordSuccess()
                        self.transitionState(.connectedHandshakeOnly, error: nil)
                    } else {
                        self.transitionState(.unverified, error: "WireGuard restarted; no fresh handshake has been observed")
                    }
                case .sshSocks5:
                    try await self.localSOCKS5Server.stop()
                    try await self.sshEngine.disconnect()
                    try await self.bringUpTunnel(for: profile)
                    if self.sshEngine.isSSHAuthenticated {
                        self.backoff.recordSuccess()
                    }
                }
            } catch {
                guard !Task.isCancelled else { return }
                self.stateLock.lock()
                self.capabilities = JaroCapabilityMatrix()
                self.stateLock.unlock()
                self.transitionState(.failed, error: error.localizedDescription)
            }
        }
        stateLock.lock()
        reconnectTask = task
        stateLock.unlock()
    }

    private func stopTransportsAndClearNetworkSettings() async {
        do { try await localSOCKS5Server.stop() }
        catch { logBuffer.append(level: "ERROR", component: "PacketTunnelProvider", message: "Unable to stop local proxy: \(error.localizedDescription)") }
        do { try await sshEngine.disconnect() }
        catch { logBuffer.append(level: "ERROR", component: "PacketTunnelProvider", message: "Unable to close SSH session: \(error.localizedDescription)") }
        do { try await wireGuardEngine.stop() }
        catch { logBuffer.append(level: "ERROR", component: "PacketTunnelProvider", message: "Unable to stop WireGuard: \(error.localizedDescription)") }
        do { try await setTunnelNetworkSettings(nil) }
        catch { logBuffer.append(level: "ERROR", component: "PacketTunnelProvider", message: "Unable to remove tunnel network settings: \(error.localizedDescription)") }
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
        var responseState = st
        if prof?.tunnelProtocol == .wireguard {
            stats = await wireGuardEngine.fetchRuntimeStats(peerPublicKeyB64: prof?.wireguard?.peerPublicKeyB64)
            caps.wireguardHandshake = stats.hasFreshHandshake
            caps.wireguardDNSConfigured = !(prof?.wireguard?.dnsServers ?? []).isEmpty
            if !stats.hasFreshHandshake {
                caps.wireguardBidirectionalTransfer = false
                caps.wireguardVerifiedHTTPS = false
                if st == .connectedHandshakeOnly || st == .connectedVerifiedHTTPS {
                    responseState = .unverified
                }
            } else if st == .unverified {
                responseState = .connectedHandshakeOnly
            }
        } else {
            stats = localSOCKS5Server.trafficAccumulator.snapshot()
            caps.sshAuthenticatedSession = sshEngine.isSSHAuthenticated
            caps.localProxyListening = localSOCKS5Server.isListening
        }
        stats.availableExtensionMemoryBytes = Self.queryAvailableExtensionMemoryBytes()

        return JaroTunnelIPCResponse(
            state: responseState,
            stats: stats,
            capabilities: caps,
            recentLogs: logBuffer.snapshot(limit: 40),
            lastError: err,
            underlyingNetwork: lastUnderlyingNetwork
        )
    }

    // MARK: - Underlying Network Classification (Connectivity Classifier rev. 2)

    private func runUnderlyingNetworkClassification(dnsQueryName: String?, httpsURLString: String?) async {
        stateLock.lock()
        let prof = activeProfile
        let vpnState = currentState.rawValue
        stateLock.unlock()

        var config = JaroConnectivityProbeConfig()
        // Resolvers: solo los servidores DNS configurados por el usuario en el perfil.
        if let wg = prof?.wireguard, let servers = wg.dnsServers {
            config.dnsResolvers = servers
        }
        config.dnsQueryName = dnsQueryName ?? ""
        // Destino HTTPS: solo la URL que el usuario suministra en el pedido IPC.
        if let s = httpsURLString, !s.isEmpty {
            config.httpsURLs = [s]
        }
        // Sin portal_url por defecto: la heurística de portal no corre si el
        // usuario no configura un destino (queda not_suspected/no_claim).
        let classifier = JaroConnectivityClassifier(transport: JaroRealProbeTransport(), config: config)
        let result = classifier.classify(vpnTunnelState: vpnState)
        stateLock.lock()
        lastUnderlyingNetwork = result
        stateLock.unlock()
        logBuffer.append(
            level: "INFO",
            component: "ConnectivityClassifier",
            message: "underlying network: ipv4=\(result.ipv4.classification.rawValue) ipv6=\(result.ipv6.classification.rawValue) (vpn=\(vpnState))"
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
