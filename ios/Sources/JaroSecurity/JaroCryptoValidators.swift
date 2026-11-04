// JARO WPF — Phase 6 Native iOS Tunnel Engine
// Module: JaroSecurity (Curve25519, OpenSSH SHA256 Fingerprint & Strict TLS X.509 Validators)
// Organization: JARO COMPLEMETS

import Crypto
import Foundation
import JaroCore
#if canImport(Security)
import Security
#endif

public enum JaroCryptoValidationError: Error, LocalizedError {
    case invalidWireGuardKeyLength
    case invalidOpenSSHPublicKeyFormat
    case hostKeyFingerprintMismatch(expected: String, actual: String)
    case tlsEvaluationFailed(String)

    public var errorDescription: String? {
        switch self {
        case .invalidWireGuardKeyLength:
            return "WireGuard key must be a valid 44-character Base64 string encoding 32 bytes"
        case .invalidOpenSSHPublicKeyFormat:
            return "OpenSSH public key string must contain '<key-type> <base64-wire-blob>'"
        case .hostKeyFingerprintMismatch(let expected, let actual):
            return "Pinned SSH host key mismatch (expected \(expected), received \(actual))"
        case .tlsEvaluationFailed(let detail):
            return "Strict X.509 TLS evaluation failed: \(detail)"
        }
    }
}

public enum JaroCryptoValidators {
    /// Validates a 32-byte Curve25519 Base64 key (WireGuard public, private, or preshared key).
    public static func isValidWireGuardKeyBase64(_ candidate: String) -> Bool {
        let trimmed = candidate.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.count == 44, trimmed.hasSuffix("="),
              let decoded = Data(base64Encoded: trimmed) else {
            return false
        }
        return decoded.count == 32
    }

    /// Computes the exact OpenSSH `SHA256:<base64-without-padding>` fingerprint from an OpenSSH public key line
    /// (`"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI..."`), matching `ssh-keygen -lf` and Python `compute_openssh_pubkey_sha256`.
    public static func computeOpenSSHPublicKeySHA256(_ openSSHPublicKeyLine: String) throws -> String {
        let parts = openSSHPublicKeyLine
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .split(whereSeparator: { $0.isWhitespace })
        guard parts.count >= 2,
              let wireBytes = Data(base64Encoded: String(parts[1])),
              !wireBytes.isEmpty else {
            throw JaroCryptoValidationError.invalidOpenSSHPublicKeyFormat
        }
        let digest = SHA256.hash(data: wireBytes)
        let b64NoPadding = Data(digest).base64EncodedString().replacingOccurrences(of: "=", with: "")
        return "SHA256:\(b64NoPadding)"
    }

    /// Verifies an OpenSSH public key string against a pinned `SHA256:...` digest.
    public static func verifyPinnedHostKey(openSSHPublicKeyLine: String, expectedSHA256: String) throws {
        let computed = try computeOpenSSHPublicKeySHA256(openSSHPublicKeyLine)
        let expected = expectedSHA256.trimmingCharacters(in: .whitespacesAndNewlines)
        guard computed == expected else {
            throw JaroCryptoValidationError.hostKeyFingerprintMismatch(expected: expected, actual: computed)
        }
    }
}

/// Enforces strict TLS 1.2/1.3 X.509 certificate + hostname (SAN) validation via Apple's `SecTrustEvaluateWithError` (Priority E).
/// Never permits insecure `NSURLCredential(trust:)` bypasses unless an explicit custom DER anchor is pinned for local lab testing.
public final class JaroTLSCertificateEvaluator: NSObject, URLSessionDelegate, @unchecked Sendable {
    private let pinnedAnchorDERCertificates: [Data]

    public init(pinnedAnchorDERCertificates: [Data] = []) {
        self.pinnedAnchorDERCertificates = pinnedAnchorDERCertificates
        super.init()
    }

    #if canImport(Security)
    public func evaluateServerTrust(_ serverTrust: SecTrust, forHost host: String) throws {
        let sslPolicy = SecPolicyCreateSSL(true, host as CFString)
        SecTrustSetPolicies(serverTrust, sslPolicy)

        if !pinnedAnchorDERCertificates.isEmpty {
            let anchors: [SecCertificate] = pinnedAnchorDERCertificates.compactMap {
                SecCertificateCreateWithData(nil, $0 as CFData)
            }
            SecTrustSetAnchorCertificates(serverTrust, anchors as CFArray)
            SecTrustSetAnchorCertificatesOnly(serverTrust, true)
        }

        var cfError: CFError?
        let trusted = SecTrustEvaluateWithError(serverTrust, &cfError)
        if !trusted {
            let reason = (cfError as Error?)?.localizedDescription ?? "Untrusted X.509 chain or hostname mismatch"
            throw JaroCryptoValidationError.tlsEvaluationFailed(reason)
        }
    }

    public func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        do {
            try evaluateServerTrust(serverTrust, forHost: challenge.protectionSpace.host)
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
        } catch {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
    #endif
}
