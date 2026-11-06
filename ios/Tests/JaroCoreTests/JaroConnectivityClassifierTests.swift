// JARO WPF — XCTest for the Swift Connectivity Classifier rev. 2 (T1–T16)
// All probes are simulated via MockTransport: these tests validate the
// classification logic, not real connectivity.

import XCTest
import JaroCore
@testable import JaroDiagnostics

final class MockProbeTransport: JaroConnectivityProbeTransport, @unchecked Sendable {
    var ipLayer: [JaroNetworkFamily: JaroIpLayerStatus] = [:]
    var dns: [String: JaroDnsStatus] = [:]              // resolver -> status
    var https: [String: JaroHttpsStatus] = [:]          // URL string -> status
    var portal: JaroPortalProbeOutcome = JaroPortalProbeOutcome(status: .notSuspected, evidence: ["mock_default"])

    func ipLayerProbe(family: JaroNetworkFamily) -> JaroIpLayerStatus {
        ipLayer[family] ?? .notProbed
    }

    func dnsProbe(resolverIP: String, queryName: String, family: JaroNetworkFamily) -> JaroDnsProbeOutcome {
        JaroDnsProbeOutcome(status: dns[resolverIP] ?? .failed, evidence: ["resolver=\(resolverIP)"])
    }

    func httpsProbe(url: URL, family: JaroNetworkFamily) -> JaroHttpsProbeOutcome {
        JaroHttpsProbeOutcome(status: https[url.absoluteString] ?? .destinationUnavailable, evidence: ["mock"])
    }

    func portalProbe(url: URL, family: JaroNetworkFamily, expectedBodyMarker: String?) -> JaroPortalProbeOutcome {
        portal
    }
}

private func makeConfig(
    resolvers: [String] = ["10.66.66.1", "fd00:6:6::1"],
    name: String = "midominio.example",
    https: [String] = ["https://midominio.example/health"],
    portal: String? = "http://midominio.example/"
) -> JaroConnectivityProbeConfig {
    JaroConnectivityProbeConfig(
        dnsResolvers: resolvers, dnsQueryName: name, httpsURLs: https, portalURL: portal
    )
}

final class JaroConnectivityClassifierTests: XCTestCase {
    private func classify(_ mock: MockProbeTransport, config: JaroConnectivityProbeConfig? = nil) -> JaroClassifierResult {
        JaroConnectivityClassifier(transport: mock, config: config ?? makeConfig()).classify()
    }

    func testT1DualStackWithoutIP() {
        let mock = MockProbeTransport()
        mock.ipLayer = [.ipv4: .unavailable, .ipv6: .unavailable]
        let r = classify(mock)
        XCTAssertEqual(r.ipv4.classification, .noConnectivity)
        XCTAssertEqual(r.ipv6.classification, .noConnectivity)
    }

    func testT2DualStackFullInternet() {
        let mock = MockProbeTransport()
        mock.ipLayer = [.ipv4: .available, .ipv6: .available]
        mock.dns = ["10.66.66.1": .ok, "fd00:6:6::1": .ok]
        mock.https = ["https://midominio.example/health": .ok]
        let r = classify(mock)
        XCTAssertEqual(r.ipv4.classification, .fullInternet)
        XCTAssertEqual(r.ipv6.classification, .fullInternet)
        XCTAssertEqual(r.ipv4.dnsStatus, .ok)
        XCTAssertEqual(r.ipv4.portalStatus, .notSuspected)
    }

    func testT3DnsTotalFailureIsolated() {
        let mock = MockProbeTransport()
        mock.ipLayer = [.ipv4: .available]
        mock.dns = ["10.66.66.1": .failed]
        mock.https = ["https://midominio.example/health": .ok]
        let r = classify(mock)
        XCTAssertEqual(r.ipv4.dnsStatus, .failed)
        XCTAssertEqual(r.ipv4.classification, .fullInternet)
    }

    func testT4HttpsBlockedWithDnsOK() {
        let mock = MockProbeTransport()
        mock.ipLayer = [.ipv4: .available]
        mock.dns = ["10.66.66.1": .ok]
        mock.https = ["https://midominio.example/health": .timeout]
        let r = classify(mock)
        XCTAssertEqual(r.ipv4.classification, .limitedAccess)
        XCTAssertEqual(r.ipv4.httpsStatus, .timeout)
    }

    func testT5IPv4FullIPv6Absent() {
        let mock = MockProbeTransport()
        mock.ipLayer = [.ipv4: .available, .ipv6: .unavailable]
        mock.dns = ["10.66.66.1": .ok]
        mock.https = ["https://midominio.example/health": .ok]
        let r = classify(mock)
        XCTAssertEqual(r.ipv4.classification, .fullInternet)
        XCTAssertEqual(r.ipv6.classification, .noConnectivity)
    }

    func testT6CaptivePortalRedirect302() {
        let mock = MockProbeTransport()
        mock.ipLayer = [.ipv4: .available]
        mock.dns = ["10.66.66.1": .ok]
        mock.https = ["https://midominio.example/health": .ok]
        mock.portal = JaroPortalProbeOutcome(status: .portalDetected, evidence: ["redirect_30x_to_login"])
        let r = classify(mock)
        XCTAssertEqual(r.ipv4.portalStatus, .portalDetected)
        XCTAssertEqual(r.ipv4.classification, .fullInternet)
    }

    func testT7HTTP500LimitedNoPortal() {
        let mock = MockProbeTransport()
        mock.ipLayer = [.ipv4: .available]
        mock.dns = ["10.66.66.1": .ok]
        mock.https = ["https://midominio.example/health": .httpErrorServer]
        let r = classify(mock)
        XCTAssertEqual(r.ipv4.classification, .limitedAccess)
        XCTAssertEqual(r.ipv4.httpsStatus, .httpErrorServer)
        XCTAssertEqual(r.ipv4.portalStatus, .notSuspected)
    }

    func testT8HttpsTimeoutWithDnsOK() {
        let mock = MockProbeTransport()
        mock.ipLayer = [.ipv4: .available]
        mock.dns = ["10.66.66.1": .ok]
        mock.https = ["https://midominio.example/health": .timeout]
        let r = classify(mock)
        XCTAssertEqual(r.ipv4.httpsStatus, .timeout)
        XCTAssertEqual(r.ipv4.classification, .limitedAccess)
    }

    func testT9TLSHandshakeFailureNoPortal() {
        let mock = MockProbeTransport()
        mock.ipLayer = [.ipv4: .available]
        mock.dns = ["10.66.66.1": .ok]
        mock.https = ["https://midominio.example/health": .tlsError]
        let r = classify(mock)
        XCTAssertEqual(r.ipv4.httpsStatus, .tlsError)
        XCTAssertEqual(r.ipv4.portalStatus, .notSuspected)
        XCTAssertEqual(r.ipv4.classification, .limitedAccess)
    }

    func testT10VPNConnectedWhileBaseNetworkDown() {
        let mock = MockProbeTransport()
        mock.ipLayer = [.ipv4: .unavailable, .ipv6: .unavailable]
        let r = JaroConnectivityClassifier(transport: mock, config: makeConfig())
            .classify(vpnTunnelState: "connected_handshake_only")
        XCTAssertEqual(r.vpnTunnelState, "connected_handshake_only")
        XCTAssertEqual(r.ipv4.classification, .noConnectivity)
        XCTAssertEqual(r.ipv6.classification, .noConnectivity)
    }

    func testT11IPv6FullIPv4Absent() {
        let mock = MockProbeTransport()
        mock.ipLayer = [.ipv4: .unavailable, .ipv6: .available]
        mock.dns = ["fd00:6:6::1": .ok]
        mock.https = ["https://midominio.example/health": .ok]
        let r = classify(mock)
        XCTAssertEqual(r.ipv4.classification, .noConnectivity)
        XCTAssertEqual(r.ipv6.classification, .fullInternet)
    }

    func testT12DnsPartial() {
        let mock = MockProbeTransport()
        mock.ipLayer = [.ipv4: .available]
        mock.dns = ["10.66.66.1": .ok, "10.66.66.2": .failed]
        mock.https = ["https://midominio.example/health": .ok]
        let config = makeConfig(resolvers: ["10.66.66.1", "10.66.66.2"])
        let r = classify(mock, config: config)
        XCTAssertEqual(r.ipv4.dnsStatus, .partial)
        XCTAssertTrue(r.ipv4.dnsEvidence.contains("resolvers_ok=1/2"))
    }

    func testT13DestinationUnavailable() {
        let mock = MockProbeTransport()
        mock.ipLayer = [.ipv4: .available]
        mock.dns = ["10.66.66.1": .ok]
        mock.https = ["https://midominio.example/health": .destinationUnavailable]
        let r = classify(mock)
        XCTAssertEqual(r.ipv4.httpsStatus, .destinationUnavailable)
        XCTAssertEqual(r.ipv4.classification, .limitedAccess)
    }

    func testT14TLSProtocolError() {
        let mock = MockProbeTransport()
        mock.ipLayer = [.ipv4: .available]
        mock.dns = ["10.66.66.1": .ok]
        mock.https = ["https://midominio.example/health": .tlsError]
        let r = classify(mock)
        XCTAssertEqual(r.ipv4.httpsStatus, .tlsError)
        XCTAssertEqual(r.ipv4.classification, .limitedAccess)
    }

    func testT15HTTP5xxDoesNotTouchPortalHeuristic() {
        let mock = MockProbeTransport()
        mock.ipLayer = [.ipv4: .available]
        mock.dns = ["10.66.66.1": .ok]
        mock.https = ["https://midominio.example/health": .httpErrorServer]
        let r = classify(mock)
        XCTAssertEqual(r.ipv4.httpsStatus, .httpErrorServer)
        XCTAssertEqual(r.ipv4.portalStatus, .notSuspected)
    }

    func testT16NoUserTargetsIpOnly() {
        let mock = MockProbeTransport()
        mock.ipLayer = [.ipv4: .available, .ipv6: .available]
        let config = makeConfig(resolvers: [], https: [], portal: nil)
        let r = classify(mock, config: config)
        XCTAssertEqual(r.ipv4.dnsStatus, .notProbed)
        XCTAssertEqual(r.ipv4.httpsStatus, .notProbed)
        XCTAssertEqual(r.ipv4.classification, .ipOnly)
        XCTAssertEqual(r.ipv6.classification, .ipOnly)
    }

    func testFamilyOfIPLiterals() {
        XCTAssertEqual(JaroConnectivityClassifier.familyOfIP("10.66.66.1"), .ipv4)
        XCTAssertEqual(JaroConnectivityClassifier.familyOfIP("fd00:6:6::1"), .ipv6)
        XCTAssertNil(JaroConnectivityClassifier.familyOfIP("midominio.example"))
    }
}
