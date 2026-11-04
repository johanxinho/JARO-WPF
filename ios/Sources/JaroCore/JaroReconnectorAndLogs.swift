// JARO WPF — Phase 6 Native iOS Tunnel Engine
// Module: JaroCore (Secret Redaction, Bounded Ring Log Buffer & Exponential Backoff Reconnector)
// Organization: JARO COMPLEMETS

import Foundation

/// Scrubs PEM private keys, OpenSSH private keys, and WireGuard PrivateKey/PresharedKey assignments
/// before any log line enters memory or crosses IPC boundaries.
public enum JaroSecretRedactor {
    private static let pemPattern = try! NSRegularExpression(
        pattern: "-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\\s\\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
        options: []
    )
    private static let wgSecretLinePattern = try! NSRegularExpression(
        pattern: "(?i)\\b(PrivateKey|PresharedKey)\\s*=\\s*(?!\\[REDACTED_)[^\\s#;]+",
        options: []
    )
    private static let inlinePasswordPattern = try! NSRegularExpression(
        pattern: "(?i)\\b(password|passwd|secret_key|passphrase)\\s*[:=]\\s*(?!\\[REDACTED_)[^\\s,;]+",
        options: []
    )

    public static func redact(_ raw: String) -> String {
        guard !raw.isEmpty else { return raw }
        var out = raw
        out = pemPattern.stringByReplacingMatches(
            in: out,
            options: [],
            range: NSRange(out.startIndex..<out.endIndex, in: out),
            withTemplate: "[REDACTED_PRIVATE_KEY]"
        )
        out = wgSecretLinePattern.stringByReplacingMatches(
            in: out,
            options: [],
            range: NSRange(out.startIndex..<out.endIndex, in: out),
            withTemplate: "$1 = [REDACTED_WG_SECRET]"
        )
        out = inlinePasswordPattern.stringByReplacingMatches(
            in: out,
            options: [],
            range: NSRange(out.startIndex..<out.endIndex, in: out),
            withTemplate: "$1=[REDACTED_SECRET]"
        )
        return out
    }
}

/// Strictly bounded thread-safe ring buffer designed to keep `NEPacketTunnelProvider` well below
/// iOS's `15 MB` jetsam RAM limit (Priority H).
public final class JaroRingLogBuffer: @unchecked Sendable {
    private let lock = NSLock()
    private let maxEntries: Int
    private let maxEntryBytes: Int
    private var entries: [String] = []
    private let isoFormatter = ISO8601DateFormatter()

    public init(maxEntries: Int = 200, maxEntryBytes: Int = 512) {
        self.maxEntries = max(16, maxEntries)
        self.maxEntryBytes = max(128, maxEntryBytes)
        self.entries.reserveCapacity(self.maxEntries)
    }

    public func append(level: String = "INFO", component: String, message: String) {
        let sanitized = JaroSecretRedactor.redact(message)
        let truncated = sanitized.count > maxEntryBytes
            ? String(sanitized.prefix(maxEntryBytes)) + "...[truncated]"
            : sanitized
        let ts = isoFormatter.string(from: Date())
        let formatted = "[\(ts)] [\(level)] [\(component)] \(truncated)"

        lock.lock()
        defer { lock.unlock() }
        if entries.count >= maxEntries {
            entries.removeFirst(entries.count - maxEntries + 1)
        }
        entries.append(formatted)
    }

    public func snapshot(limit: Int = 50) -> [String] {
        lock.lock()
        defer { lock.unlock() }
        guard limit > 0, !entries.isEmpty else { return [] }
        return Array(entries.suffix(limit))
    }

    public func clear() {
        lock.lock()
        defer { lock.unlock() }
        entries.removeAll(keepingCapacity: true)
    }
}

/// Deterministic exponential backoff reconnector with jitter and circuit breaker (Priority G),
/// ported from JARO WPF's Linux `ExponentialBackoffReconnector` to prevent infinite reconnect storms on iOS.
public final class JaroExponentialBackoff: @unchecked Sendable {
    private let lock = NSLock()
    public let baseDelaySeconds: TimeInterval
    public let maxDelaySeconds: TimeInterval
    public let multiplier: Double
    public let jitterRatio: Double
    public let maxConsecutiveFailures: Int
    public let cooldownSeconds: TimeInterval

    private var consecutiveFailures: Int = 0
    private var circuitOpenedAt: Date?

    public init(
        baseDelaySeconds: TimeInterval = 1.0,
        maxDelaySeconds: TimeInterval = 30.0,
        multiplier: Double = 2.0,
        jitterRatio: Double = 0.15,
        maxConsecutiveFailures: Int = 5,
        cooldownSeconds: TimeInterval = 60.0
    ) {
        self.baseDelaySeconds = max(0.25, baseDelaySeconds)
        self.maxDelaySeconds = max(self.baseDelaySeconds, maxDelaySeconds)
        self.multiplier = max(1.1, multiplier)
        self.jitterRatio = min(max(0.0, jitterRatio), 0.5)
        self.maxConsecutiveFailures = max(1, maxConsecutiveFailures)
        self.cooldownSeconds = max(5.0, cooldownSeconds)
    }

    public func recordSuccess() {
        lock.lock()
        defer { lock.unlock() }
        consecutiveFailures = 0
        circuitOpenedAt = nil
    }

    /// Records a failure and returns the next delay in seconds, or `nil` when the circuit breaker trips open.
    public func recordFailureAndNextDelay(now: Date = Date()) -> TimeInterval? {
        lock.lock()
        defer { lock.unlock() }

        if let opened = circuitOpenedAt {
            if now.timeIntervalSince(opened) < cooldownSeconds {
                return nil
            }
            // Cooldown elapsed: half-open probe allowed
            circuitOpenedAt = nil
            consecutiveFailures = 0
        }

        consecutiveFailures += 1
        if consecutiveFailures > maxConsecutiveFailures {
            circuitOpenedAt = now
            return nil
        }

        let exponent = Double(max(0, consecutiveFailures - 1))
        let rawDelay = min(maxDelaySeconds, baseDelaySeconds * pow(multiplier, exponent))
        let jitterSpan = rawDelay * jitterRatio
        let jitterOffset = jitterSpan > 0 ? Double.random(in: -jitterSpan...jitterSpan) : 0.0
        return max(0.1, rawDelay + jitterOffset)
    }

    public func isCircuitOpen(now: Date = Date()) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard let opened = circuitOpenedAt else { return false }
        return now.timeIntervalSince(opened) < cooldownSeconds
    }

    public var failureCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return consecutiveFailures
    }
}
