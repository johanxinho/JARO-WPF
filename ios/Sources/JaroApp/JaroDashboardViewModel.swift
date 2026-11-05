// JARO WPF — Phase 6 Native iOS Tunnel Engine
// Module: JaroApp (SwiftUI ViewModel & NETunnelProviderManager Controller)
// Organization: JARO COMPLEMETS

import Foundation
import JaroCore
import JaroDiagnostics
import JaroProfiles
import JaroSecurity
import JaroTunnelEngine
#if canImport(Combine)
import Combine
#endif
#if canImport(NetworkExtension)
import NetworkExtension
#endif

#if canImport(Combine)
@MainActor
public final class JaroDashboardViewModel: ObservableObject {
    @Published public private(set) var profiles: [JaroPortableProfile] = []
    @Published public var selectedProfileId: String?
    @Published public private(set) var tunnelState: JaroTunnelState = .remoteServerRequired
    @Published public private(set) var trafficStats = JaroTrafficStats()
    @Published public private(set) var capabilityMatrix = JaroCapabilityMatrix()
    @Published public private(set) var recentLogs: [String] = []
    @Published public var allowExpensivePaths: Bool = false
    @Published public var userMarkedMetered: Bool = false
    @Published public var isStandaloneMode: Bool = false
    @Published public private(set) var statusBannerMessage: String =
        "REMOTE_SERVER_REQUIRED: No hay servidores remotos autorizados configurados. Importe un perfil .jaroprofile o .conf propio cuando disponga de servidor."

    private let secretStore: JaroSecretStoreProtocol
    private let profileManager: JaroProfileManager
    private let logBuffer = JaroRingLogBuffer(maxEntries: 120)
    private lazy var standaloneSSHEngine = JaroNativeSSHEngine(logBuffer: logBuffer)
    private lazy var standaloneSOCKS5Server = JaroLocalSOCKS5Server(sshEngine: standaloneSSHEngine, logBuffer: logBuffer)

    public init(secretStore: JaroSecretStoreProtocol = JaroKeychainVault()) {
        self.secretStore = secretStore
        let sharedGroupURL = FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: JaroConstants.appGroupIdentifier)?
            .appendingPathComponent("Profiles", isDirectory: true)
        self.profileManager = JaroProfileManager(secretStore: secretStore, storageDirectoryURL: sharedGroupURL)
        refreshProfilesAndReadiness()
    }

    public func refreshProfilesAndReadiness() {
        profiles = profileManager.listProfiles()
        if selectedProfileId == nil {
            selectedProfileId = profiles.first?.profileId
        }
        let readiness = profileManager.evaluateRemoteReadiness()
        if profiles.isEmpty || readiness == .remoteServerRequired {
            tunnelState = .remoteServerRequired
            statusBannerMessage =
                "REMOTE_SERVER_REQUIRED: Registro de servidores remotos vacío por seguridad. Agregue su propio servidor SSH o WireGuard autorizado."
        } else if tunnelState == .remoteServerRequired {
            tunnelState = .unverified
            statusBannerMessage =
                "Perfil autorizado cargado (\(JaroConstants.verificationStatus)). Requiere prueba real en iPhone con entitlement NetworkExtension."
        }
    }

    /// Imports an SSH profile and stores the raw Ed25519 seed only in Keychain.
    /// The profile JSON contains a keychain URI, never private key material.
    public func importSSHProfile(
        profileId: String,
        displayName: String,
        host: String,
        port: Int,
        username: String,
        fingerprint: String,
        privateKeySeedBase64: String
    ) {
        let normalizedID = profileId.trimmingCharacters(in: .whitespacesAndNewlines)
        let normalizedHost = host.trimmingCharacters(in: .whitespacesAndNewlines)
        let normalizedUser = username.trimmingCharacters(in: .whitespacesAndNewlines)
        let normalizedFingerprint = fingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
        let normalizedSeed = privateKeySeedBase64.trimmingCharacters(in: .whitespacesAndNewlines)

        guard let seed = Data(base64Encoded: normalizedSeed), seed.count == 32 else {
            statusBannerMessage = "La clave debe ser la semilla privada Ed25519 de 32 bytes codificada en Base64."
            tunnelState = .failed
            return
        }

        let secretURI = "keychain://\(JaroConstants.appGroupIdentifier)/ssh/\(normalizedID)/private_key"
        do {
            let profile = JaroPortableProfile(
                profileId: normalizedID,
                displayName: displayName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? normalizedID : displayName,
                tunnelProtocol: .sshSocks5,
                host: normalizedHost,
                port: port,
                scope: "remote",
                authorized: true,
                includeDefaultRoute: false,
                includedRoutes: [],
                mtu: 1420,
                cryptoReferences: JaroCryptoReferences(keychainSecretRef: secretURI),
                sshSocks5: JaroSSHSocksSection(
                    username: normalizedUser,
                    pinnedHostKeySHA256: normalizedFingerprint,
                    localProxyPort: 1080,
                    supportsHTTPConnectBridge: true
                )
            )
            try JaroProfileManager.validateProfile(profile)
            try secretStore.storeSecret(seed, forURI: secretURI)
            do {
                try profileManager.upsertProfile(profile, persist: true)
            } catch {
                try? secretStore.deleteSecret(forURI: secretURI)
                throw error
            }
            selectedProfileId = profile.profileId
            isStandaloneMode = true
            refreshProfilesAndReadiness()
            statusBannerMessage = "Perfil SSH guardado. Modo Standalone seleccionado; listo para probar la conexión SSH."
            logBuffer.append(level: "INFO", component: "JaroApp", message: "SSH profile '\(normalizedID)' stored; private key kept in Keychain.")
            recentLogs = logBuffer.snapshot(limit: 40)
        } catch {
            tunnelState = .failed
            statusBannerMessage = JaroSecretRedactor.redact(error.localizedDescription)
            logBuffer.append(level: "ERROR", component: "JaroApp", message: error.localizedDescription)
            recentLogs = logBuffer.snapshot(limit: 40)
        }
    }

    public func importWireGuardConfiguration(
        profileId: String,
        displayName: String,
        confText: String,
        authorized: Bool
    ) {
        do {
            let imported = try profileManager.importWireGuardConf(
                profileId: profileId,
                displayName: displayName,
                confText: confText,
                authorized: authorized,
                allowGlobalRoutes: false,
                persist: true
            )
            selectedProfileId = imported.profileId
            logBuffer.append(
                level: "INFO",
                component: "JaroApp",
                message: "Imported WireGuard profile '\(imported.profileId)' cleanly into Keychain"
            )
            refreshProfilesAndReadiness()
            recentLogs = logBuffer.snapshot(limit: 40)
        } catch {
            logBuffer.append(level: "ERROR", component: "JaroApp", message: error.localizedDescription)
            statusBannerMessage = JaroSecretRedactor.redact(error.localizedDescription)
            recentLogs = logBuffer.snapshot(limit: 40)
        }
    }

    public func connectSelectedProfile() async {
        guard let pid = selectedProfileId,
              let profile = profiles.first(where: { $0.profileId == pid }) else {
            tunnelState = .remoteServerRequired
            statusBannerMessage = "REMOTE_SERVER_REQUIRED: Seleccione o importe primero un perfil autorizado."
            return
        }

        if isStandaloneMode {
            await startStandaloneProxy(for: profile)
            return
        }

        #if canImport(NetworkExtension)
        do {
            let exportedJSONData = try profileManager.exportPortableJSON(profileId: profile.profileId)
            guard let jsonString = String(data: exportedJSONData, encoding: .utf8) else { return }

            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            let manager = managers.first ?? NETunnelProviderManager()

            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = JaroConstants.packetTunnelBundleIdentifier
            proto.serverAddress = "\(profile.host):\(profile.port)"
            proto.providerConfiguration = [
                "jaro_profile_json": jsonString,
                "allow_expensive_paths": allowExpensivePaths,
                "user_marked_metered": userMarkedMetered,
            ]

            manager.protocolConfiguration = proto
            manager.localizedDescription = "JARO WPF (\(profile.displayName))"
            manager.isEnabled = true

            try await manager.saveToPreferences()
            try await manager.loadFromPreferences()
            try manager.connection.startVPNTunnel()

            tunnelState = .connecting
            statusBannerMessage = "Iniciando extensión JaroPacketTunnel para \(profile.displayName)..."
            await pollExtensionSnapshot(using: manager)
        } catch {
            tunnelState = .failed
            statusBannerMessage = JaroSecretRedactor.redact(error.localizedDescription)
            logBuffer.append(level: "ERROR", component: "NETunnelProviderManager", message: error.localizedDescription)
            recentLogs = logBuffer.snapshot(limit: 40)
        }
        #else
        await startStandaloneProxy(for: profile)
        #endif
    }

    private func startStandaloneProxy(for profile: JaroPortableProfile) async {
        guard profile.tunnelProtocol == .sshSocks5, let sshSection = profile.sshSocks5 else {
            statusBannerMessage = "El modo Standalone soporta túneles SSH/SOCKS5. WireGuard a nivel de sistema requiere extensión VPN."
            tunnelState = .failed
            return
        }
        do {
            tunnelState = .connecting
            statusBannerMessage = "Iniciando SSHv2 y proxy local Standalone..."
            try await standaloneSSHEngine.connect(profile: profile, secretStore: secretStore)
            let port = try await standaloneSOCKS5Server.start(bindHost: "127.0.0.1", port: sshSection.localProxyPort)
            tunnelState = .connectedHandshakeOnly
            capabilityMatrix.sshAuthenticatedSession = true
            capabilityMatrix.localProxyListening = true
            statusBannerMessage = "Proxy Standalone activo en 127.0.0.1:\(port). Configure el proxy Wi-Fi en Ajustes de iOS."
            logBuffer.append(level: "INFO", component: "JaroAppStandalone", message: "Standalone proxy active on 127.0.0.1:\(port)")
            recentLogs = logBuffer.snapshot(limit: 40)
        } catch {
            tunnelState = .failed
            statusBannerMessage = JaroSecretRedactor.redact("Error Standalone: \(error.localizedDescription)")
            logBuffer.append(level: "ERROR", component: "JaroAppStandalone", message: error.localizedDescription)
            recentLogs = logBuffer.snapshot(limit: 40)
        }
    }

    public func disconnectActiveTunnel() async {
        try? await standaloneSOCKS5Server.stop()
        try? await standaloneSSHEngine.disconnect()
        #if canImport(NetworkExtension)
        if let managers = try? await NETunnelProviderManager.loadAllFromPreferences(),
           let active = managers.first {
            active.connection.stopVPNTunnel()
        }
        #endif
        refreshProfilesAndReadiness()
    }

    #if canImport(NetworkExtension)
    public func requestExtensionHTTPSVerification(probeURLString: String = "https://example.com") async {
        guard let managers = try? await NETunnelProviderManager.loadAllFromPreferences(),
              let manager = managers.first,
              let session = manager.connection as? NETunnelProviderSession else {
            return
        }
        let req = JaroTunnelIPCRequest(command: .verifyHTTPSEgress, probeURLString: probeURLString)
        guard let payload = try? JSONEncoder().encode(req) else { return }

        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            try? session.sendProviderMessage(payload) { [weak self] responseData in
                if let data = responseData,
                   let decoded = try? JSONDecoder().decode(JaroTunnelIPCResponse.self, from: data) {
                    Task { @MainActor in
                        self?.applyIPCResponse(decoded)
                    }
                }
                continuation.resume(returning: ())
            }
        }
    }

    private func pollExtensionSnapshot(using manager: NETunnelProviderManager) async {
        guard let session = manager.connection as? NETunnelProviderSession,
              let payload = try? JSONEncoder().encode(JaroTunnelIPCRequest(command: .statusSnapshot)) else {
            return
        }
        try? session.sendProviderMessage(payload) { [weak self] responseData in
            guard let data = responseData,
                  let decoded = try? JSONDecoder().decode(JaroTunnelIPCResponse.self, from: data) else {
                return
            }
            Task { @MainActor in
                self?.applyIPCResponse(decoded)
            }
        }
    }
    #endif

    private func applyIPCResponse(_ response: JaroTunnelIPCResponse) {
        tunnelState = response.state
        trafficStats = response.stats
        capabilityMatrix = response.capabilities
        recentLogs = response.recentLogs
        if let err = response.lastError {
            statusBannerMessage = err
        }
    }
}
#endif
