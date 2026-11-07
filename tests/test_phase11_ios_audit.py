"""JARO WPF - Phase 11 static iOS subsystem audit.

Validates, without macOS tooling:
1. Entitlements (NetworkExtension packet-tunnel-provider + App Groups) and
   XcodeGen project coherence for the Full/Standalone/Extension targets.
2. PacketTunnelProvider lifecycle contracts: startTunnel, stopTunnel with
   clean teardown (stopTransportsAndClearNetworkSettings -> setTunnelNetworkSettings(nil)),
   handleAppMessage IPC, and WireGuard DNS/MTU/dual-stack address plumbing.
3. Connectivity Classifier rev. 2 integration: Swift module exists with the
   rev. 2 dimension/status rules, IPC command `verify_underlying_network`
   wired end to end, VPN state reported independently, and NO default
   external probe destinations.
4. WireGuardKit / libwg-go build configuration presence in the CI workflow.
"""

from __future__ import annotations

import plistlib
import pathlib
import re
import unittest

REPO = pathlib.Path(__file__).resolve().parents[1]
IOS = REPO / "ios"


class IosEntitlementsAndProjectTests(unittest.TestCase):
    def test_01_packet_tunnel_entitlements(self):
        data = (IOS / "Config" / "JaroPacketTunnel.entitlements").read_bytes()
        pl = plistlib.loads(data)
        self.assertIn("com.apple.developer.networking.networkextension", pl)
        self.assertIn(
            "packet-tunnel-provider", pl["com.apple.developer.networking.networkextension"]
        )
        self.assertIn("com.apple.security.application-groups", pl)
        self.assertEqual(pl["com.apple.security.application-groups"], ["group.com.jarocomplements.jarowpf"])

    def test_02_app_entitlements_have_app_group(self):
        for name in ("JaroApp.entitlements", "JaroAppStandalone.entitlements"):
            pl = plistlib.loads((IOS / "Config" / name).read_bytes())
            self.assertIn("group.com.jarocomplements.jarowpf", pl.get("com.apple.security.application-groups", []))

    def test_03_project_targets_and_dependencies(self):
        text = (IOS / "project.yml").read_text()
        self.assertIn("type: application", text)
        self.assertIn("type: app-extension", text)
        self.assertIn('deploymentTarget: "16.0"', text)
        for product in ("JaroCore", "JaroDiagnostics", "JaroTunnelEngine"):
            self.assertIn(f"product: {product}", text)
        self.assertIn("  JaroPacketTunnel:", text)
        self.assertIn("  JaroAppStandalone:", text)

    def test_04_extension_is_embedded_in_full_variant(self):
        text = (IOS / "project.yml").read_text()
        # The full variant (JaroApp) embeds the extension; Standalone must not.
        full_idx = text.find("  JaroApp:\n")
        standalone_idx = text.find("  JaroAppStandalone:")
        self.assertGreater(standalone_idx, full_idx)
        full_block = text[full_idx:standalone_idx]
        self.assertIn("- target: JaroPacketTunnel", full_block)
        self.assertIn("embed: true", full_block)
        standalone_block = text[standalone_idx:]
        self.assertNotIn("- target: JaroPacketTunnel", standalone_block)


class PacketTunnelProviderContractsTests(unittest.TestCase):
    SOURCE = (IOS / "Sources" / "JaroPacketTunnel" / "PacketTunnelProvider.swift").read_text()

    def test_05_lifecycle_overrides_present(self):
        for signature in (
            "public override func startTunnel(",
            "public override func stopTunnel(",
            "public override func handleAppMessage(",
        ):
            self.assertIn(signature, self.SOURCE)

    def test_06_clean_teardown_releases_transports_and_network_settings(self):
        self.assertIn("stopTransportsAndClearNetworkSettings", self.SOURCE)
        self.assertIn("try await setTunnelNetworkSettings(nil)", self.SOURCE)
        # stopTunnel must await the teardown before completing.
        stop_block = self.SOURCE[self.SOURCE.find("public override func stopTunnel"):]
        stop_block = stop_block[: stop_block.find("public override func handleAppMessage")]
        self.assertIn("stopTransportsAndClearNetworkSettings()", stop_block)

    def test_07_ssh_mode_never_installs_ip_routes(self):
        self.assertIn("SSH/SOCKS5 mode cannot install IP routes", self.SOURCE)
        self.assertIn("settings.proxySettings = proxy", self.SOURCE)

    def test_08_memory_headroom_guard(self):
        self.assertIn("minimumHeadroomBytes", self.SOURCE)
        self.assertIn("queryAvailableExtensionMemoryBytes", self.SOURCE)


class WireGuardNetworkSettingsTests(unittest.TestCase):
    ENGINE = (IOS / "Sources" / "JaroTunnelEngine" / "JaroWireGuardEngine.swift").read_text()

    def test_09_dns_mtu_addresses_plumbed_to_wireguardkit(self):
        self.assertIn("interfaceConfig.dns", self.ENGINE)
        self.assertIn("interfaceConfig.mtu", self.ENGINE)
        self.assertIn("tunnelAddressesCIDR", self.ENGINE)
        self.assertIn("dnsOverrideAuthorized", self.ENGINE)


class ConnectivityClassifierIntegrationTests(unittest.TestCase):
    CLASSIFIER = (IOS / "Sources" / "JaroCore" / "JaroConnectivityClassifier.swift").read_text()
    REAL = (IOS / "Sources" / "JaroDiagnostics" / "JaroRealProbeTransport.swift").read_text()
    MODELS = (IOS / "Sources" / "JaroCore" / "JaroModels.swift").read_text()
    PROVIDER = (IOS / "Sources" / "JaroPacketTunnel" / "PacketTunnelProvider.swift").read_text()
    TESTS = (IOS / "Tests" / "JaroCoreTests" / "JaroConnectivityClassifierTests.swift").read_text()

    def test_10_rev2_dimensions_and_rules_exist(self):
        for token in (
            "JaroIpLayerStatus", "JaroDnsStatus", "JaroHttpsStatus",
            "JaroCaptivePortalStatus", "JaroFamilyClassification",
            "JaroFamilyReport", "JaroClassifierResult",
        ):
            self.assertIn(token, self.CLASSIFIER)
        self.assertIn("if ipLayer != .available { return .noConnectivity }", self.CLASSIFIER)
        self.assertIn("if https == .notProbed { return .ipOnly }", self.CLASSIFIER)

    def test_11_https_failure_taxonomy_without_operator_attribution(self):
        for token in ("timeout", "tlsError", "httpErrorServer", "destinationUnavailable"):
            self.assertIn(f"case {token}", self.CLASSIFIER)

    def test_12_portal_heuristic_only_positive_signals(self):
        self.assertIn("redirect_30x_to_login", self.REAL)
        self.assertIn("payload_substitution_expected_marker_missing", self.REAL)
        self.assertIn("error_no_portal_claim", self.REAL)
        self.assertNotIn("portalDetected, evidence: [\"http_code=5", self.REAL)

    def test_13_ipc_command_wired_end_to_end(self):
        self.assertIn('case verifyUnderlyingNetwork = "verify_underlying_network"', self.MODELS)
        self.assertIn("case .verifyUnderlyingNetwork:", self.PROVIDER)
        self.assertIn("runUnderlyingNetworkClassification", self.PROVIDER)
        self.assertIn("underlyingNetwork: lastUnderlyingNetwork", self.PROVIDER)
        self.assertIn("public let underlyingNetwork: JaroClassifierResult?", self.MODELS)

    def test_14_vpn_state_reported_independently(self):
        self.assertIn("classify(vpnTunnelState: vpnState)", self.PROVIDER)
        self.assertIn("vpnTunnelState: String", self.CLASSIFIER)

    def test_15_no_default_external_destinations(self):
        # The classifier and its real transport must not hardcode any probe URL.
        for text in (self.CLASSIFIER, self.REAL):
            for scheme in ("https://", "http://"):
                for line in text.splitlines():
                    if scheme in line:
                        raise AssertionError(f"default destination literal found: {line.strip()[:120]}")

    def test_16_xctest_matrix_present(self):
        for case_id in (f"testT{i}" for i in range(1, 17)):
            self.assertIn(f"func {case_id}", self.TESTS)

    def test_17_swift_brace_balance(self):
        for name, text in (
            ("JaroConnectivityClassifier.swift", self.CLASSIFIER),
            ("JaroRealProbeTransport.swift", self.REAL),
            ("PacketTunnelProvider.swift", self.PROVIDER),
            ("JaroConnectivityClassifierTests.swift", self.TESTS),
            ("JaroModels.swift", self.MODELS),
        ):
            self.assertEqual(text.count("{"), text.count("}"), name)


class WireGuardKitBuildConfigTests(unittest.TestCase):
    def test_18_ci_builds_libwg_go_and_both_variants(self):
        text = (REPO / ".github" / "workflows" / "ios_build.yml").read_text()
        self.assertIn("libwg-go", text)
        self.assertIn("swift test", text)
        self.assertIn("xcodebuild", text)

    def test_19_wireguardkit_pinned(self):
        package = (IOS / "Package.swift").read_text()
        self.assertIn("WireGuardKit", package)
        self.assertIn('exact: "1.0.16-27"', package)
        workflow = (REPO / ".github" / "workflows" / "ios_build.yml").read_text()
        self.assertIn("2fec12a6e1f6e3460b6ee483aa00ad29cddadab1", workflow)

    def test_20_kit_shared_with_extension_target(self):
        project = (IOS / "project.yml").read_text()
        self.assertIn("JaroTunnelEngine", project)


class ProbeHardeningAuditTests(unittest.TestCase):
    """Contratos del endurecimiento rev. 3 de sondas (túnel bypass y 15 MB)."""

    REAL = (IOS / "Sources" / "JaroDiagnostics" / "JaroRealProbeTransport.swift").read_text()
    VIEWMODEL = (IOS / "Sources" / "JaroApp" / "JaroDashboardViewModel.swift").read_text()
    MAINVIEW = (IOS / "Sources" / "JaroApp" / "JaroMainView.swift").read_text()
    PACKAGE = (IOS / "Package.swift").read_text()

    def test_21_dns_via_udp_direct_socket_not_getaddrinfo(self):
        self.assertIn("SOCK_DGRAM", self.REAL)
        self.assertIn("JaroDNSWire.buildQuery", self.REAL)
        self.assertIn("sendto(", self.REAL)
        self.assertIn("transport=udp_direct", self.REAL)
        # El probe DNS ya no usa getaddrinfo del sistema (resolver del túnel).
        dns_section = self.REAL[self.REAL.find("public func dnsProbe"):]
        dns_section = dns_section[: dns_section.find("public func httpsProbe")]
        self.assertNotIn("getaddrinfo", dns_section)

    def test_22_interface_binding_options_present(self):
        self.assertIn("IP_BOUND_IF", self.REAL)
        self.assertIn("IPV6_BOUND_IF", self.REAL)
        self.assertIn("if_nametoindex", self.REAL)
        self.assertIn("physicalInterfaceName", self.REAL)

    def test_23_ephemeral_urlsession_and_immediate_invalidation(self):
        self.assertIn("URLSessionConfiguration.ephemeral", self.REAL)
        self.assertIn("waitsForConnectivity = false", self.REAL)
        # https + portal (el comentario de cabecera también lo menciona).
        self.assertGreaterEqual(self.REAL.count("session.finishTasksAndInvalidate()"), 2)
        self.assertIn("urlCache = nil", self.REAL)

    def test_24_no_default_public_destinations(self):
        for line in self.REAL.splitlines():
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("*"):
                continue
            for scheme in ("https://", "http://"):
                self.assertNotIn(scheme, line, f"URL literal inesperada: {stripped[:120]}")

    def test_25_viewmodel_publishes_underlying_network_separately(self):
        self.assertIn("@Published public private(set) var underlyingNetwork: JaroClassifierResult?", self.VIEWMODEL)
        self.assertIn("classify(vpnTunnelState: tunnelState.rawValue)", self.VIEWMODEL)
        self.assertIn("response.underlyingNetwork != nil", self.VIEWMODEL)
        self.assertIn(".verifyUnderlyingNetwork", self.VIEWMODEL)

    def test_26_probe_config_user_owned_and_persisted(self):
        self.assertIn("public func saveProbeConfig(", self.VIEWMODEL)
        self.assertIn("jaro_probe_user_config_v1", self.VIEWMODEL)
        self.assertIn("struct JaroProbeUserConfig", (IOS / "Sources" / "JaroCore" / "JaroConnectivityClassifier.swift").read_text())

    def test_27_standalone_runs_classifier_in_app_process(self):
        # El clasificador corre en la app (red física) y por IPC solo si hay extensión.
        self.assertIn("if !isStandaloneMode, await sendUnderlyingNetworkRequestToExtension() {", self.VIEWMODEL)
        self.assertIn("probeTransportFactory()", self.VIEWMODEL)

    def test_28_swiftui_buttons_have_actions(self):
        # Heurística: cada Button( de la vista principal debe tener un closure
        # con al menos una llamada (ningún botón decorativo).
        text = self.MAINVIEW
        count = text.count("Button(")
        self.assertGreater(count, 0)
        for match in re.finditer(r"Button\(([^)]*)\)\s*\{([^}]*)\}", text, re.S):
            body = match.group(2).strip()
            self.assertTrue(body, f"Button sin acción: {match.group(1)}")
            self.assertGreater(len(body), 2, f"Button vacío: {match.group(1)}")
        # Botones nuevos conectados al clasificador y a la config de sondas.
        self.assertIn("runConnectivityClassification()", self.MAINVIEW)
        self.assertIn("saveProbeConfig(", self.MAINVIEW)

    def test_29_ui_shows_both_states_explicitly(self):
        self.assertIn("Red Subyacente (Clasificador rev. 2)", self.MAINVIEW)
        self.assertIn("Estado de la VPN (extensión / proxy)", self.MAINVIEW)
        self.assertIn("se reporta por separado", self.MAINVIEW)
        self.assertIn("\"AllowedIPs / rutas incluidas\"", self.MAINVIEW)

    def test_30_test_target_includes_app_module(self):
        self.assertIn('"JaroApp",', self.PACKAGE)


if __name__ == "__main__":
    unittest.main()
