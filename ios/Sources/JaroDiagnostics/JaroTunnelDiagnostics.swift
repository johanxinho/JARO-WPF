// JARO WPF — Phase 6 Native iOS Tunnel Engine
// Module: JaroDiagnostics (NWPathMonitor Cost Guard & Strict HTTPS Egress Verifier — Priority F)
// Organization: JARO COMPLEMETS

import Foundation
import JaroCore
import JaroSecurity
#if canImport(Darwin)
import Darwin
#endif
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
    public let dnsResolutionSucceeded: Bool?
    public let errorDescription: String?

    public init(
        httpsVerified: Bool,
        tlsVerified: Bool,
        captivePortalSuspected: Bool,
        statusCode: Int?,
        latencyMs: Double,
        bytesTransferred: Int,
        dnsResolutionSucceeded: Bool? = nil,
        errorDescription: String? = nil
    ) {
        self.httpsVerified = httpsVerified
        self.tlsVerified = tlsVerified
        self.captivePortalSuspected = captivePortalSuspected
        self.statusCode = statusCode
        self.latencyMs = latencyMs
        self.bytesTransferred = bytesTransferred
        self.dnsResolutionSucceeded = dnsResolutionSucceeded
        self.errorDescription = errorDescription
    }
}

public struct JaroDNSResolutionResult: Codable, Equatable, Sendable {
    public let succeeded: Bool
    public let queryName: String
    public let configuredServers: [String]
    public let errorDescription: String?
}

/// Uses the operating-system resolver after WireGuardKit has installed NEDNSSettings.
/// A successful lookup proves name resolution, not that no DNS packet escaped another path.
public final class JaroDNSResolutionDiagnostic: @unchecked Sendable {
    private final class CompletionBox: @unchecked Sendable {
        private let lock = NSLock()
        private var completed = false
        private let continuation: CheckedContinuation<JaroDNSResolutionResult, Never>

        init(_ continuation: CheckedContinuation<JaroDNSResolutionResult, Never>) {
            self.continuation = continuation
        }

        func finish(_ result: JaroDNSResolutionResult) {
            lock.lock()
            guard !completed else { lock.unlock(); return }
            completed = true
            lock.unlock()
            continuation.resume(returning: result)
        }
    }

    public init() {}

    public static func isValidQueryName(_ raw: String) -> Bool {
        let name = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty, name.utf8.count <= 253,
              IPv4Address(name) == nil, IPv6Address(name) == nil else { return false }
        return name.split(separator: ".", omittingEmptySubsequences: false).allSatisfy { label in
            guard (1...63).contains(label.utf8.count),
                  label.first != "-", label.last != "-" else { return false }
            return label.utf8.allSatisfy { byte in
                (65...90).contains(byte) || (97...122).contains(byte) || (48...57).contains(byte) || byte == 45
            }
        }
    }

    public func resolve(
        queryName rawName: String,
        configuredServers: [String],
        timeoutSeconds: TimeInterval = 8
    ) async -> JaroDNSResolutionResult {
        let name = rawName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard Self.isValidQueryName(name) else {
            return JaroDNSResolutionResult(succeeded: false, queryName: name, configuredServers: configuredServers, errorDescription: "DNS query name is not a valid hostname")
        }
        guard !configuredServers.isEmpty,
              configuredServers.allSatisfy({ IPv4Address($0) != nil || IPv6Address($0) != nil }) else {
            return JaroDNSResolutionResult(succeeded: false, queryName: name, configuredServers: configuredServers, errorDescription: "No valid profile DNS server is configured")
        }
        #if canImport(Darwin)
        return await withCheckedContinuation { continuation in
            let box = CompletionBox(continuation)
            DispatchQueue.global(qos: .utility).async {
                var hints = addrinfo()
                hints.ai_family = AF_UNSPEC
                hints.ai_socktype = SOCK_STREAM
                var result: UnsafeMutablePointer<addrinfo>?
                let code = getaddrinfo(name, nil, &hints, &result)
                if let result { freeaddrinfo(result) }
                box.finish(JaroDNSResolutionResult(
                    succeeded: code == 0,
                    queryName: name,
                    configuredServers: configuredServers,
                    errorDescription: code == 0 ? nil : String(cString: gai_strerror(code))
                ))
            }
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + max(0.5, timeoutSeconds)) {
                box.finish(JaroDNSResolutionResult(
                    succeeded: false,
                    queryName: name,
                    configuredServers: configuredServers,
                    errorDescription: "System DNS resolution timed out"
                ))
            }
        }
        #else
        return JaroDNSResolutionResult(succeeded: false, queryName: name, configuredServers: configuredServers, errorDescription: "System resolver is unavailable on this platform")
        #endif
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
        let hostnameResolutionExpected = IPv4Address(targetHost) == nil && IPv6Address(targetHost) == nil

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
                    dnsResolutionSucceeded: hostnameResolutionExpected ? true : nil,
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
                    dnsResolutionSucceeded: hostnameResolutionExpected ? true : nil,
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
                dnsResolutionSucceeded: hostnameResolutionExpected ? true : nil,
                errorDescription: (statusOK && bodyOK) ? nil : "Unexpected HTTP status (\(httpResp.statusCode)) or payload mismatch"
            )
        } catch {
            let elapsedMs = Date().timeIntervalSince(start) * 1000.0
            let nsError = error as NSError
            let dnsFailed = hostnameResolutionExpected && nsError.domain == NSURLErrorDomain &&
                (nsError.code == NSURLErrorCannotFindHost || nsError.code == NSURLErrorDNSLookupFailed)
            return JaroHTTPSProbeResult(
                httpsVerified: false,
                tlsVerified: false,
                captivePortalSuspected: false,
                statusCode: nil,
                latencyMs: elapsedMs,
                bytesTransferred: 0,
                dnsResolutionSucceeded: dnsFailed ? false : nil,
                errorDescription: JaroSecretRedactor.redact(error.localizedDescription)
            )
        }
    }
}
