// JARO WPF — Real probe transport for the connectivity classifier (iOS)
// Module: JaroDiagnostics
//
// Sondas reales (NWPathMonitor + getaddrinfo + URLSession). Todos los
// destinos provienen de la configuración del usuario; no hay URLs públicas
// por defecto. El portal cautivo solo se marca ante redirecciones 302/307 a
// endpoints de login o sustitución de payload (marcador esperado del usuario);
// un fallo de red o TLS nunca marca portal cautivo.

import Foundation
import Network

public struct JaroRealProbeTransport: JaroConnectivityProbeTransport {
    public init() {}

    // MARK: - Capa IP (NWPathMonitor por familia)

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

    // MARK: - DNS (getaddrinfo ligado a familia; resolvers del usuario)

    public func dnsProbe(resolverIP: String, queryName: String, family: JaroNetworkFamily) -> JaroDnsProbeOutcome {
        var hints = addrinfo()
        hints.ai_family = family == .ipv6 ? AF_INET6 : AF_INET
        hints.ai_socktype = SOCK_STREAM
        var result: UnsafeMutablePointer<addrinfo>?
        let rc = getaddrinfo(queryName, nil, &hints, &result)
        defer { if let result { freeaddrinfo(result) } }
        if rc == 0, result != nil {
            return JaroDnsProbeOutcome(status: .ok, evidence: ["resolver=\(resolverIP)", "getaddrinfo_rc=0"])
        }
        if rc == EAI_NONAME || rc == EAI_NODATA {
            return JaroDnsProbeOutcome(status: .failed, evidence: ["resolver=\(resolverIP)", "eai_no_name"])
        }
        return JaroDnsProbeOutcome(status: .failed, evidence: ["resolver=\(resolverIP)", "eai_rc=\(rc)"])
    }

    // MARK: - HTTPS (URLSession con taxonomía de fallo)

    public func httpsProbe(url: URL, family: JaroNetworkFamily) -> JaroHttpsProbeOutcome {
        if let urlFamily = JaroConnectivityClassifier.familyOfURL(url), urlFamily != family {
            return JaroHttpsProbeOutcome(status: .destinationUnavailable, evidence: ["url_other_family"])
        }
        final class Box: @unchecked Sendable {
            var value = JaroHttpsProbeOutcome(status: .destinationUnavailable, evidence: ["no_response"])
        }
        let box = Box()
        var request = URLRequest(url: url)
        request.httpMethod = "HEAD"
        request.timeoutInterval = 3.0
        let semaphore = DispatchSemaphore(value: 0)
        let task = URLSession.shared.dataTask(with: request) { _, response, error in
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
        _ = semaphore.wait(timeout: .now() + 6.0)
        return box.value
    }

    // MARK: - Portal cautivo (heurística, solo puertos http)

    public func portalProbe(url: URL, family: JaroNetworkFamily, expectedBodyMarker: String?) -> JaroPortalProbeOutcome {
        if let urlFamily = JaroConnectivityClassifier.familyOfURL(url), urlFamily != family {
            return JaroPortalProbeOutcome(status: .notSuspected, evidence: ["portal_target_other_family"])
        }
        final class Box: @unchecked Sendable {
            var value = JaroPortalProbeOutcome(status: .notSuspected, evidence: ["no_claim"])
        }
        let box = Box()
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.timeoutInterval = 3.0
        let semaphore = DispatchSemaphore(value: 0)
        let task = URLSession.shared.dataTask(with: request) { body, response, error in
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
        _ = semaphore.wait(timeout: .now() + 6.0)
        return box.value
    }
}
