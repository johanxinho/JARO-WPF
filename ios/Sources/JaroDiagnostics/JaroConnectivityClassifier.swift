// JARO WPF — Connectivity Classifier rev. 2 (iOS diagnostics)
// Module: JaroDiagnostics
//
// Port of `core/classifier/` (Python rev. 2) to Swift:
// - IPv4 and IPv6 are classified independently; a missing family never
//   degrades a working family.
// - IP layer, DNS, HTTPS and captive-portal are separate dimensions; an
//   isolated DNS failure does not imply a restricted network.
// - HTTPS failures are typed (timeout / TLS / HTTP 5xx / destination
//   unreachable) and are NEVER attributed to the operator by themselves.
// - Captive portal is a heuristic only (HTTP 302/307 to login endpoints, or
//   user-marker payload substitution on port 80). 5xx and TLS errors never
//   mark a portal.
// - Every destination comes from the user's configuration; no default
//   external destinations exist.
// - The VPN tunnel state is reported separately and never alters the
//   classification of the underlying network.

import Foundation

public enum JaroIpLayerStatus: String, Codable, Sendable {
    case available
    case unavailable
    case notProbed = "not_probed"
}

public enum JaroDnsStatus: String, Codable, Sendable {
    case ok
    case partial
    case failed
    case notProbed = "not_probed"
}

public enum JaroHttpsStatus: String, Codable, Sendable {
    case ok
    case destinationUnavailable = "destination_unavailable"
    case tlsError = "tls_error"
    case httpErrorServer = "http_error_server"
    case timeout
    case notProbed = "not_probed"
}

public enum JaroCaptivePortalStatus: String, Codable, Sendable {
    case notSuspected = "not_suspected"
    case portalDetected = "portal_detected"
}

public enum JaroFamilyClassification: String, Codable, Sendable {
    case fullInternet = "full_internet"
    case limitedAccess = "limited_access"
    case ipOnly = "ip_only"
    case noConnectivity = "no_connectivity"
}

public enum JaroNetworkFamily: String, CaseIterable, Sendable {
    case ipv4
    case ipv6
}

/// Deterministic per-family rules (mirrors `classification_for` in Python).
public func jaroClassification(
    ipLayer: JaroIpLayerStatus,
    https: JaroHttpsStatus
) -> JaroFamilyClassification {
    if ipLayer != .available { return .noConnectivity }
    if https == .notProbed { return .ipOnly }
    if https == .ok { return .fullInternet }
    return .limitedAccess
}

public struct JaroFamilyReport: Codable, Equatable, Sendable {
    public var family: JaroNetworkFamily
    public var ipLayer: JaroIpLayerStatus
    public var dnsStatus: JaroDnsStatus
    public var dnsEvidence: [String]
    public var httpsStatus: JaroHttpsStatus
    public var httpsEvidence: [String]
    public var portalStatus: JaroCaptivePortalStatus
    public var portalEvidence: [String]
    public var classification: JaroFamilyClassification

    public init(
        family: JaroNetworkFamily,
        ipLayer: JaroIpLayerStatus,
        dnsStatus: JaroDnsStatus,
        dnsEvidence: [String],
        httpsStatus: JaroHttpsStatus,
        httpsEvidence: [String],
        portalStatus: JaroCaptivePortalStatus,
        portalEvidence: [String]
    ) {
        self.family = family
        self.ipLayer = ipLayer
        self.dnsStatus = dnsStatus
        self.dnsEvidence = dnsEvidence
        self.httpsStatus = httpsStatus
        self.httpsEvidence = httpsEvidence
        self.portalStatus = portalStatus
        self.portalEvidence = portalEvidence
        self.classification = jaroClassification(ipLayer: ipLayer, https: httpsStatus)
    }
}

/// Underlying-network snapshot. VPN state is carried for reporting only.
public struct JaroClassifierResult: Codable, Equatable, Sendable {
    public var ipv4: JaroFamilyReport
    public var ipv6: JaroFamilyReport
    public var vpnTunnelState: String
    public var generatedAt: Date

    public init(ipv4: JaroFamilyReport, ipv6: JaroFamilyReport, vpnTunnelState: String, generatedAt: Date = Date()) {
        self.ipv4 = ipv4
        self.ipv6 = ipv6
        self.vpnTunnelState = vpnTunnelState
        self.generatedAt = generatedAt
    }
}

public struct JaroConnectivityProbeConfig: Sendable {
    /// User-configured DNS resolvers (IP literals; family inferred from format).
    public var dnsResolvers: [String]
    /// User-configured name to resolve.
    public var dnsQueryName: String
    /// User-configured HTTPS probe URLs (no defaults).
    public var httpsURLs: [String]
    /// Optional user-configured portal URL for the captive-portal heuristic.
    public var portalURL: String?
    /// Optional expected body marker for payload-substitution detection.
    public var expectedBodyMarker: String?

    public init(
        dnsResolvers: [String] = [],
        dnsQueryName: String = "",
        httpsURLs: [String] = [],
        portalURL: String? = nil,
        expectedBodyMarker: String? = nil
    ) {
        self.dnsResolvers = dnsResolvers
        self.dnsQueryName = dnsQueryName
        self.httpsURLs = httpsURLs
        self.portalURL = portalURL
        self.expectedBodyMarker = expectedBodyMarker
    }

    public static let loginMarkers: [String] = ["login", "portal", "auth", "captive", "activar", "saldo"]
}

// MARK: - Injectable transport

public struct JaroDnsProbeOutcome: Sendable {
    public var status: JaroDnsStatus
    public var evidence: [String]
    public init(status: JaroDnsStatus, evidence: [String] = []) {
        self.status = status
        self.evidence = evidence
    }
}

public struct JaroHttpsProbeOutcome: Sendable {
    public var status: JaroHttpsStatus
    public var httpCode: Int?
    public var evidence: [String]
    public init(status: JaroHttpsStatus, httpCode: Int? = nil, evidence: [String] = []) {
        self.status = status
        self.httpCode = httpCode
        self.evidence = evidence
    }
}

public struct JaroPortalProbeOutcome: Sendable {
    public var status: JaroCaptivePortalStatus
    public var evidence: [String]
    public init(status: JaroCaptivePortalStatus, evidence: [String] = []) {
        self.status = status
        self.evidence = evidence
    }
}

public protocol JaroConnectivityProbeTransport: Sendable {
    func ipLayerProbe(family: JaroNetworkFamily) -> JaroIpLayerStatus
    func dnsProbe(resolverIP: String, queryName: String, family: JaroNetworkFamily) -> JaroDnsProbeOutcome
    func httpsProbe(url: URL, family: JaroNetworkFamily) -> JaroHttpsProbeOutcome
    func portalProbe(url: URL, family: JaroNetworkFamily, expectedBodyMarker: String?) -> JaroPortalProbeOutcome
}

// MARK: - Classifier

public struct JaroConnectivityClassifier: Sendable {
    public var transport: JaroConnectivityProbeTransport
    public var config: JaroConnectivityProbeConfig

    public init(transport: JaroConnectivityProbeTransport, config: JaroConnectivityProbeConfig) {
        self.transport = transport
        self.config = config
    }

    public func classify(vpnTunnelState: String = "disconnected") -> JaroClassifierResult {
        let ipv4 = classifyFamily(.ipv4)
        let ipv6 = classifyFamily(.ipv6)
        return JaroClassifierResult(ipv4: ipv4, ipv6: ipv6, vpnTunnelState: vpnTunnelState)
    }

    private func classifyFamily(_ family: JaroNetworkFamily) -> JaroFamilyReport {
        let ipLayer = transport.ipLayerProbe(family: family)
        let dns = dnsDimension(family)
        let https = httpsDimension(family)
        let portal = portalDimension(family)
        return JaroFamilyReport(
            family: family,
            ipLayer: ipLayer,
            dnsStatus: dns.status,
            dnsEvidence: dns.evidence,
            httpsStatus: https.status,
            httpsEvidence: https.evidence,
            portalStatus: portal.status,
            portalEvidence: portal.evidence
        )
    }

    private func dnsDimension(_ family: JaroNetworkFamily) -> (status: JaroDnsStatus, evidence: [String]) {
        let resolvers = config.dnsResolvers.filter { Self.familyOfIP($0) == family }
        guard !resolvers.isEmpty, !config.dnsQueryName.isEmpty else {
            return (.notProbed, ["no_dns_targets_configured"])
        }
        var evidence: [String] = []
        var okCount = 0
        for resolver in resolvers {
            let outcome = transport.dnsProbe(resolverIP: resolver, queryName: config.dnsQueryName, family: family)
            evidence.append(contentsOf: outcome.evidence)
            if outcome.status == .ok { okCount += 1 }
        }
        if okCount == resolvers.count { return (.ok, evidence) }
        if okCount > 0 { return (.partial, evidence + ["resolvers_ok=\(okCount)/\(resolvers.count)"]) }
        return (.failed, evidence)
    }

    private func httpsDimension(_ family: JaroNetworkFamily) -> (status: JaroHttpsStatus, evidence: [String]) {
        let urls = config.httpsURLs.compactMap { URL(string: $0) }.filter { Self.familyOfURL($0) == family }
        guard !urls.isEmpty else { return (.notProbed, ["no_https_targets_configured"]) }
        var evidence: [String] = []
        var best = JaroHttpsStatus.destinationUnavailable
        for url in urls {
            let outcome = transport.httpsProbe(url: url, family: family)
            evidence.append(contentsOf: outcome.evidence)
            if outcome.status == .ok { return (.ok, evidence) }
            best = outcome.status
        }
        return (best, evidence)
    }

    private func portalDimension(_ family: JaroNetworkFamily) -> (status: JaroCaptivePortalStatus, evidence: [String]) {
        guard let portalURLString = config.portalURL, let url = URL(string: portalURLString) else {
            return (.notSuspected, ["no_portal_target_configured"])
        }
        if let urlFamily = Self.familyOfURL(url), urlFamily != family {
            return (.notSuspected, ["portal_target_other_family"])
        }
        let outcome = transport.portalProbe(url: url, family: family, expectedBodyMarker: config.expectedBodyMarker)
        return (outcome.status, outcome.evidence)
    }

    static func familyOfIP(_ value: String) -> JaroNetworkFamily? {
        var addr = in6_addr()
        if value.contains(":") && inet_pton(AF_INET6, value, &addr) == 1 { return .ipv6 }
        var v4 = in_addr()
        if inet_pton(AF_INET, value, &v4) == 1 { return .ipv4 }
        return nil
    }

    static func familyOfURL(_ url: URL) -> JaroNetworkFamily? {
        guard let host = url.host else { return nil }
        return familyOfIP(host)
    }
}
