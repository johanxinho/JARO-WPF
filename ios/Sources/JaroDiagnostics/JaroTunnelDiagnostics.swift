// JARO WPF — Phase 6 Native iOS Tunnel Engine
// Module: JaroDiagnostics (NWPathMonitor Cost Guard & Strict HTTPS Egress Verifier — Priority F)
// Organization: JARO COMPLEMETS

import Foundation
import JaroCore
import JaroSecurity
#if canImport(Network)
import Network
#endif
#if canImport(CFNetwork)
import CFNetwork
#endif

public struct JaroHTTPSProbeResult: Codable, Equatable, Sendable {
    public let httpsVerified: Bool
    public let tlsVerified: Bool
    public let captivePortalSuspected: Bool
    public let statusCode: Int?
    public let latencyMs: Double
    public let bytesTransferred: Int
    public let errorDescription: String?

    public init(
        httpsVerified: Bool,
        tlsVerified: Bool,
        captivePortalSuspected: Bool,
        statusCode: Int?,
        latencyMs: Double,
        bytesTransferred: Int,
        errorDescription: String? = nil
    ) {
        self.httpsVerified = httpsVerified
        self.tlsVerified = tlsVerified
        self.captivePortalSuspected = captivePortalSuspected
        self.statusCode = statusCode
        self.latencyMs = latencyMs
        self.bytesTransferred = bytesTransferred
        self.errorDescription = errorDescription
    }
}

/// Observes live network path changes via Apple's `Network.framework` (`NWPathMonitor`), enforcing
/// JARO WPF's `CostManager` invariant: NEVER assume Wi-Fi or Ethernet is free when `isExpensive`,
/// `isConstrained`, or an explicit user metered override is active.
public final class JaroPathCostMonitor: @unchecked Sendable {
    private let lock = NSLock()
    private let logBuffer: JaroRingLogBuffer
    private var userMarkedMeteredOverride: Bool?
    private var allowExpensivePaths: Bool
    private var latestSnapshot = JaroPathCostSnapshot(
        interfaceKind: "unknown",
        isExpensive: true,
        isConstrained: false
    )

    #if canImport(Network)
    private var monitor: NWPathMonitor?
    private let monitorQueue = DispatchQueue(label: "com.jarocomplements.jarowpf.pathmonitor", qos: .utility)
    #endif

    public init(
        allowExpensivePaths: Bool = false,
        userMarkedMeteredOverride: Bool? = nil,
        logBuffer: JaroRingLogBuffer
    ) {
        self.allowExpensivePaths = allowExpensivePaths
        self.userMarkedMeteredOverride = userMarkedMeteredOverride
        self.logBuffer = logBuffer
    }

    public func updateCostPolicy(allowExpensivePaths: Bool, userMarkedMeteredOverride: Bool?) {
        lock.lock()
        self.allowExpensivePaths = allowExpensivePaths
        self.userMarkedMeteredOverride = userMarkedMeteredOverride
        lock.unlock()
    }

    public func currentSnapshot() -> JaroPathCostSnapshot {
        lock.lock()
        defer { lock.unlock() }
        return latestSnapshot
    }

    public func start(onPathTransition: (@Sendable (JaroPathCostSnapshot, Bool) -> Void)? = nil) {
        #if canImport(Network)
        stop()
        let nwMonitor = NWPathMonitor()
        nwMonitor.pathUpdateHandler = { [weak self] path in
            guard let self = self else { return }
            let kind: String
            if path.usesInterfaceType(.wifi) {
                kind = "wifi"
            } else if path.usesInterfaceType(.cellular) {
                kind = "cellular"
            } else if path.usesInterfaceType(.wiredEthernet) {
                kind = "wiredEthernet"
            } else if path.usesInterfaceType(.loopback) {
                kind = "loopback"
            } else {
                kind = "other"
            }

            self.lock.lock()
            let userOverride = self.userMarkedMeteredOverride
            let allowExp = self.allowExpensivePaths
            self.lock.unlock()

            let snap = JaroPathCostSnapshot(
                interfaceKind: kind,
                isExpensive: path.isExpensive,
                isConstrained: path.isConstrained,
                userMarkedMetered: userOverride,
                allowExpensivePaths: allowExp
            )
            let isSatisfied = (path.status == .satisfied)

            self.lock.lock()
            self.latestSnapshot = snap
            self.lock.unlock()

            self.logBuffer.append(
                level: "INFO",
                component: "JaroPathCostMonitor",
                message: "Path=\(path.status) kind=\(kind) expensive=\(path.isExpensive) constrained=\(path.isConstrained) policyOK=\(snap.satisfiesTunnelPolicy)"
            )
            onPathTransition?(snap, isSatisfied)
        }
        lock.lock()
        self.monitor = nwMonitor
        lock.unlock()
        nwMonitor.start(queue: monitorQueue)
        #else
        _ = onPathTransition
        #endif
    }

    public func stop() {
        #if canImport(Network)
        lock.lock()
        let mon = monitor
        monitor = nil
        lock.unlock()
        mon?.cancel()
        #endif
    }
}

/// Executes bounded (`<= 8 KB`), strict TLS X.509 HTTPS probes across either the system WireGuard `utun`
/// route or the local `127.0.0.1:<port>` `HTTP CONNECT` / `SOCKS5` tunnel bridge.
/// Distinguishes DNS resolution from genuine HTTPS egress and detects captive portal interceptions.
public final class JaroHTTPSEgressDiagnostic: @unchecked Sendable {
    private let maxProbeBytes: Int

    public init(maxProbeBytes: Int = 8192) {
        self.maxProbeBytes = max(1024, maxProbeBytes)
    }

    public func verifyHTTPSEgress(
        url: URL,
        expectedStatus: Int = 200,
        expectedBodySubstring: String? = nil,
        localHTTPConnectProxyPort: Int? = nil,
        timeoutSeconds: TimeInterval = 6.0,
        pinnedAnchorDERCertificates: [Data] = []
    ) async -> JaroHTTPSProbeResult {
        let start = Date()
        guard url.scheme?.lowercased() == "https", let targetHost = url.host else {
            return JaroHTTPSProbeResult(
                httpsVerified: false,
                tlsVerified: false,
                captivePortalSuspected: false,
                statusCode: nil,
                latencyMs: 0,
                bytesTransferred: 0,
                errorDescription: "Diagnostic probe URL must use https://"
            )
        }

        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = timeoutSeconds
        config.timeoutIntervalForResource = timeoutSeconds
        config.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        config.waitsForConnectivity = false

        #if canImport(CFNetwork)
        if let proxyPort = localHTTPConnectProxyPort, (1024...65535).contains(proxyPort) {
            config.connectionProxyDictionary = [
                kCFNetworkProxiesHTTPEnable as String: 1,
                kCFNetworkProxiesHTTPProxy as String: "127.0.0.1",
                kCFNetworkProxiesHTTPPort as String: proxyPort,
                "HTTPSEnable": 1,
                "HTTPSProxy": "127.0.0.1",
                "HTTPSPort": proxyPort,
            ]
        }
        #endif

        let tlsDelegate = JaroTLSCertificateEvaluator(pinnedAnchorDERCertificates: pinnedAnchorDERCertificates)
        let session = URLSession(configuration: config, delegate: tlsDelegate, delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }

        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("identity", forHTTPHeaderField: "Accept-Encoding")
        request.setValue("JARO-WPF-iOS/0.6", forHTTPHeaderField: "User-Agent")

        do {
            let (data, response) = try await session.data(for: request)
            let elapsedMs = Date().timeIntervalSince(start) * 1000.0
            let boundedData = data.prefix(maxProbeBytes)

            guard let httpResp = response as? HTTPURLResponse else {
                return JaroHTTPSProbeResult(
                    httpsVerified: false,
                    tlsVerified: false,
                    captivePortalSuspected: false,
                    statusCode: nil,
                    latencyMs: elapsedMs,
                    bytesTransferred: boundedData.count,
                    errorDescription: "Non-HTTP response received"
                )
            }

            let finalHost = httpResp.url?.host?.lowercased()
            let redirectedCrossOrigin = (finalHost != nil && finalHost != targetHost.lowercased())
            let statusRedirect = (300...399).contains(httpResp.statusCode)
            if redirectedCrossOrigin || statusRedirect {
                return JaroHTTPSProbeResult(
                    httpsVerified: false,
                    tlsVerified: true,
                    captivePortalSuspected: true,
                    statusCode: httpResp.statusCode,
                    latencyMs: elapsedMs,
                    bytesTransferred: boundedData.count,
                    errorDescription: "Redirect or cross-origin response suspected as captive portal (\(httpResp.statusCode))"
                )
            }

            let statusOK = (httpResp.statusCode == expectedStatus)
            var bodyOK = true
            if let needle = expectedBodySubstring, !needle.isEmpty {
                let text = String(data: boundedData, encoding: .utf8) ?? ""
                bodyOK = text.contains(needle)
            }

            return JaroHTTPSProbeResult(
                httpsVerified: statusOK && bodyOK,
                tlsVerified: true,
                captivePortalSuspected: !bodyOK && statusOK,
                statusCode: httpResp.statusCode,
                latencyMs: elapsedMs,
                bytesTransferred: boundedData.count,
                errorDescription: (statusOK && bodyOK) ? nil : "Unexpected HTTP status (\(httpResp.statusCode)) or payload mismatch"
            )
        } catch {
            let elapsedMs = Date().timeIntervalSince(start) * 1000.0
            return JaroHTTPSProbeResult(
                httpsVerified: false,
                tlsVerified: false,
                captivePortalSuspected: false,
                statusCode: nil,
                latencyMs: elapsedMs,
                bytesTransferred: 0,
                errorDescription: JaroSecretRedactor.redact(error.localizedDescription)
            )
        }
    }
}
