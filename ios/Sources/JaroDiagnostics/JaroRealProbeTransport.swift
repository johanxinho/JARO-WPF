// JARO WPF — Real probe transport for the connectivity classifier (iOS)
// Module: JaroDiagnostics
//
// Endurecimiento rev. 3:
// - DNS por socket UDP ligero (SOCK_DGRAM) directamente a la IP del resolver
//   configurado por el usuario (RD=1, QDCOUNT=1), NUNCA vía getaddrinfo del
//   sistema (que usaría el resolver del túnel cuando la VPN está activa).
// - Binding opcional a la interfaz física subyacente con IP_BOUND_IF (IPv4) /
//   IPV6_BOUND_IF (IPv6) usando if_nametoindex, para que las sondas midan la
//   red física (Cellular/Wi-Fi) y no el propio túnel.
// - HTTPS/portal con URLSessionConfiguration.ephemeral (cero caché),
//   waitsForConnectivity = false, timeouts cortos y finishTasksAndInvalidate()
//   inmediato tras cada sonda para respetar el techo de 15 MB de la extensión.
// - Límite documentado: URLSession no permite binding de interfaz; para una
//   medición completa fuera del túnel, ejecutar el clasificador desde el
//   proceso de la app principal (Standalone/diagnóstico), no desde la
//   extensión con el túnel activo.
// - Todos los destinos provienen de la configuración del usuario; sin URLs
//   públicas por defecto. El portal cautivo es solo heurística.

import Foundation
import Network
import JaroCore
import Security

// MARK: - DNS wire format (parity with core/classifier/transport.py)

public enum JaroDNSWire {
    /// Builds a standard DNS query: RD=1, QDCOUNT=1, one question (A or AAAA).
    public static func buildQuery(name: String, qtype: UInt16) -> Data {
        var tid = Data(count: 2)
        _ = tid.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 2, $0.baseAddress!) }
        var packet = tid
        packet.append(contentsOf: [0x01, 0x00]) // flags: RD=1
        packet.append(contentsOf: [0x00, 0x01]) // QDCOUNT=1
        packet.append(contentsOf: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00]) // AN/NS/AR=0
        for label in name.split(separator: ".", omittingEmptySubsequences: true) {
            let bytes = Array(label.utf8)
            packet.append(UInt8(bytes.count))
            packet.append(contentsOf: bytes)
        }
        packet.append(0x00)
        var q = qtype.bigEndian
        var c = UInt16(1).bigEndian // IN
        withUnsafeBytes(of: &q) { packet.append(contentsOf: $0) }
        withUnsafeBytes(of: &c) { packet.append(contentsOf: $0) }
        return packet
    }

    /// Parses a DNS response: verifies the transaction ID and returns (rcode, ancount).
    public static func parseResponse(_ data: Data, tid: Data) -> Result<(rcode: Int, ancount: Int), JaroDNSParseError> {
        guard data.count >= 12 else { return .failure(.truncated) }
        guard data.prefix(2) == tid.prefix(2) else { return .failure(.tidMismatch) }
        let rcode = Int(data[3]) & 0x0F
        let ancount = (Int(data[6]) << 8) | Int(data[7])
        return .success((rcode, ancount))
    }
}

public enum JaroDNSParseError: Error, Equatable {
    case truncated
    case tidMismatch
}

// MARK: - Interface binding (Darwin)

public enum JaroInterfaceBinding {
    /// Binds a socket to the physical interface by name (e.g. "en0", "pdp_ip0").
    /// IP_BOUND_IF = 25 (IPv4), IPV6_BOUND_IF = 125 (IPv6) on Darwin.
    public static func bind(_ fd: Int32, family: JaroNetworkFamily, interfaceName: String) -> Bool {
        let index = if_nametoindex(interfaceName)
        guard index != 0 else { return false }
        if family == .ipv6 {
            var idx: UInt32 = index
            return setsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF, &idx, socklen_t(MemoryLayout<UInt32>.size)) == 0
        }
        var idx: UInt32 = index
        return setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &idx, socklen_t(MemoryLayout<UInt32>.size)) == 0
    }
}

/// sockaddr seguro por familia (evita casts fuera de buffer).
public enum JaroSockAddr {
    case v4(sockaddr_in)
    case v6(sockaddr_in6)

    var familyValue: Int32 {
        switch self {
        case .v4: return AF_INET
        case .v6: return AF_INET6
        }
    }

    /// Ejecuta body con un puntero válido al sockaddr y su longitud.
    func withSockPtr<R>(_ body: (UnsafePointer<sockaddr>, socklen_t) -> R) -> R {
        switch self {
        case .v4(var a):
            return withUnsafeBytes(of: &a) { raw in
                body(raw.baseAddress!.assumingMemoryBound(to: sockaddr.self), socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        case .v6(var a):
            return withUnsafeBytes(of: &a) { raw in
                body(raw.baseAddress!.assumingMemoryBound(to: sockaddr.self), socklen_t(MemoryLayout<sockaddr_in6>.size))
            }
        }
    }

    static func parse(_ ip: String, port: UInt16) -> JaroSockAddr? {
        if ip.contains(":") {
            var addr6 = sockaddr_in6()
            addr6.sin6_family = sa_family_t(AF_INET6)
            addr6.sin6_port = port.bigEndian
            var v6 = in6_addr()
            guard inet_pton(AF_INET6, ip, &v6) == 1 else { return nil }
            addr6.sin6_addr = v6
            return .v6(addr6)
        }
        var addr4 = sockaddr_in()
        addr4.sin_family = sa_family_t(AF_INET)
        addr4.sin_port = port.bigEndian
        var v4 = in_addr()
        guard inet_pton(AF_INET, ip, &v4) == 1 else { return nil }
        addr4.sin_addr = v4
        return .v4(addr4)
    }
}

// MARK: - Transport

public struct JaroRealProbeTransport: JaroConnectivityProbeTransport {
    /// Nombre de la interfaz física a la que vincular los sockets UDP (opcional).
    /// Ej.: "en0" (Wi-Fi), "pdp_ip0" (celular). Si es nil, no se vincula.
    public var physicalInterfaceName: String?
    public var dnsTimeout: TimeInterval
    public var httpTimeout: TimeInterval

    public init(
        physicalInterfaceName: String? = nil,
        dnsTimeout: TimeInterval = 2.0,
        httpTimeout: TimeInterval = 3.0
    ) {
        self.physicalInterfaceName = physicalInterfaceName
        self.dnsTimeout = dnsTimeout
        self.httpTimeout = httpTimeout
    }

    // MARK: Capa IP (NWPathMonitor por familia)

    public func ipLayerProbe(family: JaroNetworkFamily) -> JaroIpLayerStatus {
        final class Box: @unchecked Sendable {
            var value: JaroIpLayerStatus = .notProbed
        }
        let box = Box()
        let semaphore = DispatchSemaphore(value: 0)
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { path in
            let satisfied = path.status == .satisfied
            switch family {
            case .ipv4:
                box.value = (satisfied && path.supportsIPv4) ? .available : .unavailable
            case .ipv6:
                box.value = (satisfied && path.supportsIPv6) ? .available : .unavailable
            }
            semaphore.signal()
        }
        monitor.start(queue: DispatchQueue(label: "com.jarocomplements.jarowpf.ipprobe.\(family.rawValue)"))
        _ = semaphore.wait(timeout: .now() + 2.0)
        monitor.cancel()
        return box.value
    }

    // MARK: DNS (UDP directo al resolver del usuario; getaddrinfo NO se usa)

    public func dnsProbe(resolverIP: String, queryName: String, family: JaroNetworkFamily) -> JaroDnsProbeOutcome {
        let evidence: [String] = [
            "resolver=\(resolverIP)",
            "family=\(family.rawValue)",
            "transport=udp_direct",
            physicalInterfaceName.map { "bound_if=\($0)" } ?? "bound_if=none",
        ]
        guard let sockAddr = JaroSockAddr.parse(resolverIP, port: 53) else {
            return JaroDnsProbeOutcome(status: .failed, evidence: evidence + ["invalid_resolver_ip"])
        }
        let qtype: UInt16 = family == .ipv6 ? 28 : 1 // AAAA / A
        let query = JaroDNSWire.buildQuery(name: queryName, qtype: qtype)
        let fd = socket(sockAddr.familyValue, SOCK_DGRAM, 0)
        guard fd >= 0 else {
            return JaroDnsProbeOutcome(status: .failed, evidence: evidence + ["socket_open_failed=\(errno)"])
        }
        defer { close(fd) }
        if let ifName = physicalInterfaceName {
            let boundFamily: JaroNetworkFamily = sockAddr.familyValue == AF_INET6 ? .ipv6 : .ipv4
            guard JaroInterfaceBinding.bind(fd, family: boundFamily, interfaceName: ifName) else {
                return JaroDnsProbeOutcome(status: .failed, evidence: evidence + ["interface_bind_failed"])
            }
        }
        var timeout = timeval(tv_sec: Int(dnsTimeout), tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        let sent: Int = sockAddr.withSockPtr { saPtr, saLen in
            query.withUnsafeBytes { qptr in
                sendto(fd, qptr.baseAddress, query.count, 0, saPtr, saLen)
            }
        }
        guard sent == query.count else {
            return JaroDnsProbeOutcome(status: .failed, evidence: evidence + ["send_failed=\(errno)"])
        }
        var response = Data(repeating: 0, count: 4096)
        let received = response.withUnsafeMutableBytes { ptr -> Int in
            recvfrom(fd, ptr.baseAddress, 4096, 0, nil, nil)
        }
        if received <= 0 {
            return JaroDnsProbeOutcome(status: .failed, evidence: evidence + ["timeout_or_no_reply"])
        }
        response = response.prefix(received)
        switch JaroDNSWire.parseResponse(response, tid: query.prefix(2)) {
        case .failure(let err):
            return JaroDnsProbeOutcome(status: .failed, evidence: evidence + ["parse_error=\(err)"])
        case .success(let parsed):
            if parsed.rcode != 0 {
                return JaroDnsProbeOutcome(status: .failed, evidence: evidence + ["rcode=\(parsed.rcode)"])
            }
            if parsed.ancount > 0 {
                return JaroDnsProbeOutcome(status: .ok, evidence: evidence + ["answers=\(parsed.ancount)"])
            }
            return JaroDnsProbeOutcome(status: .failed, evidence: evidence + ["noerror_no_answers"])
        }
    }

    // MARK: HTTPS (URLSession efímero + invalidación inmediata)

    public func httpsProbe(url: URL, family: JaroNetworkFamily) -> JaroHttpsProbeOutcome {
        if let urlFamily = JaroConnectivityClassifier.familyOfURL(url), urlFamily != family {
            return JaroHttpsProbeOutcome(status: .destinationUnavailable, evidence: ["url_other_family"])
        }
        final class Box: @unchecked Sendable {
            var value = JaroHttpsProbeOutcome(status: .destinationUnavailable, evidence: ["no_response"])
        }
        let box = Box()
        let semaphore = DispatchSemaphore(value: 0)
        // Ephemeral: cero caché en RAM/disco; sin cookies; sesión invalidada al salir.
        let config = URLSessionConfiguration.ephemeral
        config.waitsForConnectivity = false
        config.timeoutIntervalForRequest = httpTimeout
        config.timeoutIntervalForResource = httpTimeout + 2.0
        config.urlCache = nil
        let session = URLSession(configuration: config)
        var request = URLRequest(url: url)
        request.httpMethod = "HEAD"
        request.timeoutInterval = httpTimeout
        let task = session.dataTask(with: request) { _, response, error in
            defer { semaphore.signal() }
            if let error = error as? URLError {
                switch error.code {
                case .timedOut:
                    box.value = JaroHttpsProbeOutcome(status: .timeout, evidence: ["timeout"])
                case .cannotFindHost, .cannotConnectToHost, .networkConnectionLost,
                     .notConnectedToInternet, .dnsLookupFailed, .resourceUnavailable:
                    box.value = JaroHttpsProbeOutcome(status: .destinationUnavailable, evidence: ["unreachable"])
                default:
                    box.value = JaroHttpsProbeOutcome(status: .tlsError, evidence: ["tls_or_transport_error"])
                }
                return
            }
            guard let http = response as? HTTPURLResponse else { return }
            if http.statusCode >= 500 {
                box.value = JaroHttpsProbeOutcome(
                    status: .httpErrorServer, httpCode: http.statusCode, evidence: ["http_code=\(http.statusCode)"]
                )
            } else {
                box.value = JaroHttpsProbeOutcome(
                    status: .ok, httpCode: http.statusCode, evidence: ["http_code=\(http.statusCode)"]
                )
            }
        }
        task.resume()
        _ = semaphore.wait(timeout: .now() + httpTimeout + 3.0)
        // Libera la sesión inmediatamente (Jetsam < 15 MB en la extensión).
        session.finishTasksAndInvalidate()
        return box.value
    }

    // MARK: Portal cautivo (heurística; URLSession efímero también)

    public func portalProbe(url: URL, family: JaroNetworkFamily, expectedBodyMarker: String?) -> JaroPortalProbeOutcome {
        if let urlFamily = JaroConnectivityClassifier.familyOfURL(url), urlFamily != family {
            return JaroPortalProbeOutcome(status: .notSuspected, evidence: ["portal_target_other_family"])
        }
        final class Box: @unchecked Sendable {
            var value = JaroPortalProbeOutcome(status: .notSuspected, evidence: ["no_claim"])
        }
        let box = Box()
        let semaphore = DispatchSemaphore(value: 0)
        let config = URLSessionConfiguration.ephemeral
        config.waitsForConnectivity = false
        config.timeoutIntervalForRequest = httpTimeout
        config.urlCache = nil
        let session = URLSession(configuration: config)
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.timeoutInterval = httpTimeout
        let task = session.dataTask(with: request) { body, response, error in
            defer { semaphore.signal() }
            if error != nil {
                // Un portal nunca se marca por fallo de red: solo heurística positiva.
                box.value = JaroPortalProbeOutcome(status: .notSuspected, evidence: ["error_no_portal_claim"])
                return
            }
            guard let http = response as? HTTPURLResponse else { return }
            let location = (http.allHeaderFields["Location"] as? String) ?? ""
            let lowered = location.lowercased()
            if (http.statusCode == 302 || http.statusCode == 307)
                && JaroConnectivityProbeConfig.loginMarkers.contains(where: { lowered.contains($0) }) {
                box.value = JaroPortalProbeOutcome(
                    status: .portalDetected, evidence: ["redirect_30x_to_login=\(String(location.prefix(80)))"]
                )
                return
            }
            if http.statusCode == 200, let marker = expectedBodyMarker,
               let text = body.map({ String(data: $0, encoding: .utf8) ?? "" }),
               !text.contains(marker) {
                box.value = JaroPortalProbeOutcome(
                    status: .portalDetected, evidence: ["payload_substitution_expected_marker_missing"]
                )
                return
            }
            box.value = JaroPortalProbeOutcome(status: .notSuspected, evidence: ["http_code=\(http.statusCode)"])
        }
        task.resume()
        _ = semaphore.wait(timeout: .now() + httpTimeout + 3.0)
        session.finishTasksAndInvalidate()
        return box.value
    }

    // MARK: - Helpers de dirección

}
