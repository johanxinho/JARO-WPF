// JARO WPF — Phase 6 Native iOS Tunnel Engine
// Module: JaroCoreTests (XCTest Suite for Core, Security & Profile Invariants)
// Organization: JARO COMPLEMETS

import Foundation
import JaroCore
import JaroDiagnostics
import JaroProfiles
import JaroSecurity
import JaroTunnelEngine
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

    func testSharedKeychainAccessGroupMustMatchAppGroupIdentifier() throws {
        let expectedGroup = JaroConstants.appGroupIdentifier
        XCTAssertEqual(
            try JaroKeychainAccessGroupResolver.resolve(
                referenceGroup: expectedGroup,
                configuredAccessGroup: expectedGroup
            ),
            expectedGroup
        )
        XCTAssertThrowsError(
            try JaroKeychainAccessGroupResolver.resolve(
                referenceGroup: expectedGroup,
                configuredAccessGroup: ""
            )
        )
        XCTAssertThrowsError(
            try JaroKeychainAccessGroupResolver.resolve(
                referenceGroup: "group.example.attacker",
                configuredAccessGroup: "group.example.attacker"
            )
        )
        XCTAssertThrowsError(
            try JaroKeychainAccessGroupResolver.resolve(
                referenceGroup: expectedGroup,
                configuredAccessGroup: "ABCDE12345.\(expectedGroup)"
            )
        )
    }

    func testWireGuardDNSIPv4IPv6FullTunnelConsentAndPortableRoundTrip() throws {
        let vault = JaroInMemorySecretVault()
        let manager = JaroProfileManager(secretStore: vault)
        let privateKey = Data(repeating: 0x31, count: 32).base64EncodedString()
        let peerKey = Data(repeating: 0x42, count: 32).base64EncodedString()
        let conf = """
        [Interface]
        PrivateKey = \(privateKey)
        Address = 10.77.0.2/24, fd77::2/64
        DNS = 10.77.0.1, fd77::1
        MTU = 1420

        [Peer]
        PublicKey = \(peerKey)
        Endpoint = 203.0.113.8:51820
        AllowedIPs = 0.0.0.0/0, ::/0
        PersistentKeepalive = 25
        """

        XCTAssertThrowsError(try manager.importWireGuardConf(
            profileId: "wg-consent-missing-dns", displayName: "No DNS consent", confText: conf, authorized: true,
            allowGlobalRoutes: true, allowDNSOverride: false
        ))
        XCTAssertThrowsError(try manager.importWireGuardConf(
            profileId: "wg-consent-missing-routes", displayName: "No route consent", confText: conf, authorized: true,
            allowGlobalRoutes: false, allowDNSOverride: true
        ))

        let profile = try manager.importWireGuardConf(
            profileId: "wg-dual-stack-full", displayName: "Dual-stack full tunnel", confText: conf, authorized: true,
            allowGlobalRoutes: true, allowDNSOverride: true
        )
        XCTAssertTrue(profile.includeDefaultRoute)
        XCTAssertEqual(profile.wireguard?.tunnelAddressesCIDR, ["10.77.0.2/24", "fd77::2/64"])
        XCTAssertEqual(profile.wireguard?.dnsServers, ["10.77.0.1", "fd77::1"])
        XCTAssertEqual(profile.wireguard?.dnsOverrideAuthorized, true)

        let exported = try manager.exportPortableJSON(profileId: profile.profileId)
        XCTAssertFalse(String(data: exported, encoding: .utf8)!.contains(privateKey))
        let imported = try manager.importPortableJSON(
            exported, persist: false, allowGlobalRoutes: true, allowDNSOverride: true
        )
        XCTAssertEqual(imported.wireguard?.dnsServers, ["10.77.0.1", "fd77::1"])
        XCTAssertEqual(imported.wireguard?.tunnelAddressesCIDR?.count, 2)
        XCTAssertThrowsError(try JaroProfileManager(secretStore: vault).importPortableJSON(exported))
    }

    func testWireGuardRejectsInvalidDNSMTUIncompleteFullTunnelAndMultiplePeers() throws {
        let privateKey = Data(repeating: 0x31, count: 32).base64EncodedString()
        let peerKey = Data(repeating: 0x42, count: 32).base64EncodedString()
        let manager = JaroProfileManager(secretStore: JaroInMemorySecretVault())
        func config(address: String, dns: String, mtu: String, allowed: String, extraPeer: String = "") -> String {
            """
            [Interface]
            PrivateKey = \(privateKey)
            Address = \(address)
            DNS = \(dns)
            MTU = \(mtu)
            [Peer]
            PublicKey = \(peerKey)
            Endpoint = 203.0.113.8:51820
            AllowedIPs = \(allowed)
            \(extraPeer)
            """
        }
        for invalid in [
            config(address: "10.77.0.2/24", dns: "resolver.example", mtu: "1420", allowed: "10.77.0.0/24"),
            config(address: "10.77.0.2/24", dns: "10.77.0.1", mtu: "9000", allowed: "10.77.0.0/24"),
            config(address: "10.77.0.2/24", dns: "10.77.0.1", mtu: "1420", allowed: "0.0.0.0/0"),
            config(address: "bad-cidr", dns: "10.77.0.1", mtu: "1420", allowed: "10.77.0.0/24"),
            config(address: "10.77.0.2/24", dns: "10.77.0.1", mtu: "1420", allowed: "10.77.0.0/24", extraPeer: "[Peer]\nPublicKey = \(peerKey)\nEndpoint = 203.0.113.9:51820\nAllowedIPs = 10.78.0.0/24")
        ] {
            XCTAssertThrowsError(try manager.importWireGuardConf(
                profileId: "wg-invalid-\(UUID().uuidString.prefix(8))", displayName: "Invalid", confText: invalid,
                authorized: true, allowGlobalRoutes: true, allowDNSOverride: true
            ))
        }
    }

    func testWireGuardUAPIStatsAreBoundToConfiguredPeerAndFreshness() {
        let now = Int64(Date().timeIntervalSince1970)
        let targetKey = Data(repeating: 0x11, count: 32).base64EncodedString()
        let otherHex = String(repeating: "22", count: 32)
        let targetHex = String(repeating: "11", count: 32)
        let uapi = """
        public_key=\(otherHex)
        last_handshake_time_sec=\(now)
        rx_bytes=900
        tx_bytes=800
        public_key=\(targetHex)
        last_handshake_time_sec=\(now)
        rx_bytes=120
        tx_bytes=95
        """
        let selected = JaroWireGuardEngine.parseUAPIRuntimeConfiguration(uapi, peerPublicKeyB64: targetKey)
        XCTAssertEqual(selected.rxBytes, 120)
        XCTAssertEqual(selected.txBytes, 95)
        XCTAssertTrue(selected.hasFreshHandshake)

        let wrongPeer = JaroWireGuardEngine.parseUAPIRuntimeConfiguration(uapi, peerPublicKeyB64: Data(repeating: 0x33, count: 32).base64EncodedString())
        XCTAssertEqual(wrongPeer.rxBytes, 0)
        XCTAssertEqual(wrongPeer.txBytes, 0)
        XCTAssertFalse(wrongPeer.hasFreshHandshake)
    }

    func testDNSQueryNameValidationDoesNotContactPublicResolvers() {
        XCTAssertTrue(JaroDNSResolutionDiagnostic.isValidQueryName("router.lab.internal"))
        XCTAssertTrue(JaroDNSResolutionDiagnostic.isValidQueryName("my-owned-domain.example"))
        XCTAssertFalse(JaroDNSResolutionDiagnostic.isValidQueryName("10.0.0.1"))
        XCTAssertFalse(JaroDNSResolutionDiagnostic.isValidQueryName("bad..label"))
        XCTAssertFalse(JaroDNSResolutionDiagnostic.isValidQueryName("-invalid.example"))
    }
}
