// JARO WPF — XCTests for probe hardening (UDP DNS wire parity, ViewModel
// separation of underlying network vs VPN state, probe config persistence).

import XCTest
import JaroCore
@testable import JaroDiagnostics
@testable import JaroApp

final class JaroDNSWireTests: XCTestCase {
    func testBuildQueryParityWithPython() {
        // core/classifier/transport.py::_build_dns_query: RD=1, QDCOUNT=1.
        let q = JaroDNSWire.buildQuery(name: "midominio.example", qtype: 1)
        XCTAssertEqual(q[2], 0x01)           // RD bit
        XCTAssertEqual(q[3] & 0x0F, 0x00)    // RCODE=0 in query
        XCTAssertEqual(Int(q[4]) << 8 | Int(q[5]), 1) // QDCOUNT=1
        XCTAssertEqual(q[6], 0x00); XCTAssertEqual(q[7], 0x00) // ANCOUNT=0
        // Encoded name: \x0bmidominio\x07example\x00 (labels, sin puntos).
        let namePart = q.suffix(from: 12)
        XCTAssertEqual(Array(namePart.prefix(19)), Array("\u{0B}midominio\u{07}example\u{00}".utf8))
        // Ends with QTYPE=A(1) + QCLASS=IN(1)
        XCTAssertEqual(q.suffix(4), Data([0x00, 0x01, 0x00, 0x01]))
    }

    func testParseResponseValidatesTidAndCounts() {
        var resp = Data([0xDE, 0xAD, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00])
        resp.append(Data(repeating: 0x00, count: 16))
        let parsed = JaroDNSWire.parseResponse(resp, tid: Data([0xDE, 0xAD]))
        guard case .success(let value) = parsed else { return XCTFail("parse failed") }
        XCTAssertEqual(value.rcode, 0)
        XCTAssertEqual(value.ancount, 2)
        guard case .failure(.tidMismatch) = JaroDNSWire.parseResponse(resp, tid: Data([0xBE, 0xEF])) else {
            return XCTFail("expected tidMismatch")
        }
        guard case .failure(.truncated) = JaroDNSWire.parseResponse(Data([0x00, 0x01]), tid: Data([0x00, 0x01])) else {
            return XCTFail("expected truncated")
        }
    }

    func testSockAddrParseFamilies() {
        let v4 = JaroSockAddr.parse("10.66.66.1", port: 53)
        guard case .v4? = v4 else { return XCTFail("v4 expected") }
        let v6 = JaroSockAddr.parse("fd00:6:6::1", port: 53)
        guard case .v6? = v6 else { return XCTFail("v6 expected") }
        XCTAssertNil(JaroSockAddr.parse("no-es-ip", port: 53))
    }
}

final class JaroViewModelSeparationTests: XCTestCase {
private func makeViewModel() -> JaroDashboardViewModel {
    let mock = MockProbeTransport()
    mock.ipLayer = [.ipv4: .available, .ipv6: .available]
    return JaroDashboardViewModel(
        secretStore: InMemorySecretStore(),
        probeTransportFactory: { mock },
        defaults: UserDefaults(suiteName: "jaro-tests-\(UUID().uuidString)")!
    )
}

    func testUnderlyingNetworkIndependentFromTunnelState() async {
        let vm = makeViewModel()
        // Sin perfiles: la VPN queda en remote_server_required.
        XCTAssertEqual(vm.tunnelState, .remoteServerRequired)
        await vm.runConnectivityClassification()
        // El clasificador corre igual y su resultado NO depende del estado VPN.
        let result = try? XCTUnwrap(vm.underlyingNetwork)
        XCTAssertEqual(result?.vpnTunnelState, JaroTunnelState.remoteServerRequired.rawValue)
        // Clase de red: sin destinos configurados el techo es IP_ONLY.
        XCTAssertEqual(result?.ipv4.classification, .ipOnly)
        XCTAssertEqual(result?.ipv6.classification, .ipOnly)
        XCTAssertEqual(result?.ipv4.dnsStatus, .notProbed)
        XCTAssertEqual(result?.ipv6.httpsStatus, .notProbed)
    }

    func testProbeConfigPersistenceAndUsage() async {
        let defaults = UserDefaults(suiteName: "jaro-tests-\(UUID().uuidString)")!
        let vm = JaroDashboardViewModel(
            secretStore: InMemorySecretStore(),
            probeTransportFactory: { MockProbeTransport() },
            defaults: defaults
        )
        let config = JaroProbeUserConfig(
            dnsResolvers: ["10.66.66.1"], dnsQueryName: "midominio.example",
            httpsURLs: ["https://midominio.example/health"]
        )
        vm.saveProbeConfig(config, defaults: defaults)
        XCTAssertEqual(vm.probeConfig, config)
        // Recarga desde persistencia.
        let vm2 = JaroDashboardViewModel(
            secretStore: InMemorySecretStore(),
            probeTransportFactory: { MockProbeTransport() },
            defaults: defaults
        )
        XCTAssertEqual(vm2.probeConfig, config)
        // Con destinos configurados y capa IP no disponible: NO_CONNECTIVITY.
        await vm2.runConnectivityClassification()
        let result = try? XCTUnwrap(vm2.underlyingNetwork)
        XCTAssertEqual(result?.ipv4.classification, .noConnectivity)
    }
}

/// Almacén de secretos en memoria para pruebas (no toca Keychain).
final class InMemorySecretStore: JaroSecretStoreProtocol, @unchecked Sendable {
    private var storage: [String: Data] = [:]
    func storeSecret(_ secretData: Data, forURI keychainURI: String) throws { storage[keychainURI] = secretData }
    func loadSecret(forURI keychainURI: String) throws -> Data {
        guard let data = storage[keychainURI] else { throw NSError(domain: "test", code: 404) }
        return data
    }
    func deleteSecret(forURI keychainURI: String) throws { storage.removeValue(forKey: keychainURI) }
}
