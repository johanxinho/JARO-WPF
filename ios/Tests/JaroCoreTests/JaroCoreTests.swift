// JARO WPF — Phase 6 Native iOS Tunnel Engine
// Module: JaroCoreTests (XCTest Suite for Core, Security & Profile Invariants)
// Organization: JARO COMPLEMETS

import Foundation
import JaroCore
import JaroProfiles
import JaroSecurity
import XCTest

final class JaroCoreTests: XCTestCase {
    func testEmptyProfileManagerReturnsRemoteServerRequired() {
        let vault = JaroInMemorySecretVault()
        let manager = JaroProfileManager(secretStore: vault)
        XCTAssertTrue(manager.listProfiles().isEmpty)
        XCTAssertEqual(manager.evaluateRemoteReadiness(), .remoteServerRequired)
    }

    func testWireGuardConfImportExtractsSecretsToKeychainAndBlocksGlobalRoutes() throws {
        let vault = JaroInMemorySecretVault()
        let manager = JaroProfileManager(secretStore: vault)
        let privKey = Data(repeating: 0x11, count: 32).base64EncodedString()
        let pubKey = Data(repeating: 0x22, count: 32).base64EncodedString()

        let globalConf = """
        [Interface]
        PrivateKey = \(privKey)
        Address = 10.77.0.2/24

        [Peer]
        PublicKey = \(pubKey)
        Endpoint = 198.51.100.10:51820
        AllowedIPs = 0.0.0.0/0
        """
        XCTAssertThrowsError(
            try manager.importWireGuardConf(
                profileId: "wg-global-blocked",
                displayName: "Blocked Global",
                confText: globalConf,
                authorized: true,
                allowGlobalRoutes: false
            )
        )

        let splitConf = """
        [Interface]
        PrivateKey = \(privKey)
        Address = 10.77.0.2/24
        MTU = 1420

        [Peer]
        PublicKey = \(pubKey)
        Endpoint = 198.51.100.10:51820
        AllowedIPs = 10.77.0.0/24
        PersistentKeepalive = 25
        """
        let imported = try manager.importWireGuardConf(
            profileId: "wg-split-ok",
            displayName: "Authorized Split WG",
            confText: splitConf,
            authorized: true,
            allowGlobalRoutes: false
        )
        XCTAssertFalse(imported.includeDefaultRoute)

        let exportedJSON = String(data: try manager.exportPortableJSON(profileId: "wg-split-ok"), encoding: .utf8)!
        XCTAssertFalse(exportedJSON.contains(privKey), "Exported .jaroprofile JSON must NEVER contain PrivateKey")
        XCTAssertEqual(try vault.loadSecretString(forURI: imported.cryptoReferences.keychainSecretRef), privKey)
        XCTAssertEqual(manager.evaluateRemoteReadiness(), .unverified)
    }

    func testSecretRedactorScrubsKeysAndExponentialBackoffTripsCircuitBreaker() {
        let leaked = "Error loading PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= in tunnel"
        let scrubbed = JaroSecretRedactor.redact(leaked)
        XCTAssertFalse(scrubbed.contains("AAAA"))
        XCTAssertTrue(scrubbed.contains("[REDACTED_WG_SECRET]"))

        let backoff = JaroExponentialBackoff(
            baseDelaySeconds: 0.5,
            maxDelaySeconds: 4.0,
            multiplier: 2.0,
            jitterRatio: 0.0,
            maxConsecutiveFailures: 3,
            cooldownSeconds: 30.0
        )
        let t0 = Date()
        XCTAssertNotNil(backoff.recordFailureAndNextDelay(now: t0))
        XCTAssertNotNil(backoff.recordFailureAndNextDelay(now: t0))
        XCTAssertNotNil(backoff.recordFailureAndNextDelay(now: t0))
        XCTAssertNil(backoff.recordFailureAndNextDelay(now: t0))
        XCTAssertTrue(backoff.isCircuitOpen(now: t0))
    }

    func testOpenSSHPublicKeySHA256FingerprintMatchesStandardWireFormat() throws {
        // Minimal synthetic ssh-ed25519 wire blob
        let fakeWire = Data("ssh-ed25519-test-wire-blob".utf8).base64EncodedString()
        let line = "ssh-ed25519 \(fakeWire) jaro@test"
        let fp = try JaroCryptoValidators.computeOpenSSHPublicKeySHA256(line)
        XCTAssertTrue(fp.hasPrefix("SHA256:"))
        XCTAssertNoThrow(try JaroCryptoValidators.verifyPinnedHostKey(openSSHPublicKeyLine: line, expectedSHA256: fp))
        XCTAssertThrowsError(
            try JaroCryptoValidators.verifyPinnedHostKey(
                openSSHPublicKeyLine: line,
                expectedSHA256: "SHA256:0000000000000000000000000000000000000000000"
            )
        )
    }
}
