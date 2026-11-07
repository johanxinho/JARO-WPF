// JARO WPF — Phase 6 Native iOS Tunnel Engine
// Module: JaroApp (SwiftUI Main View — Profiles, Tunnel Telemetry, Diagnostics & Tigo Info Separation)
// Organization: JARO COMPLEMETS

#if canImport(SwiftUI)
import JaroCore
import SwiftUI
import CryptoKit
#if canImport(UIKit)
import UIKit
#endif

public struct JaroMainView: View {
    @ObservedObject private var viewModel: JaroDashboardViewModel
    @State private var showingImportSheet = false
    @State private var showingSSHSheet = false
    @State private var wgProfileIdInput = ""
    @State private var wgDisplayNameInput = ""
    @State private var wgConfTextInput = ""
    @State private var allowDNSOverride = false
    @State private var allowFullTunnel = false
    @State private var httpsProbeURL = ""
    @State private var dnsQueryName = ""
    @State private var probeResolversInput = ""
    @State private var probeHttpsInput = ""
    @State private var probeQueryNameInput = ""

    public init(viewModel: JaroDashboardViewModel) {
        self.viewModel = viewModel
    }

    public var body: some View {
        NavigationStack {
            List {
                statusSection
                vpnDetailSection
                underlyingNetworkSection
                probeConfigSection
                profilesSection
                costPolicySection
                telemetryAndCapabilitiesSection
                logsSection
                carrierSeparationInfoSection
            }
            .navigationTitle("JARO WPF — iOS")
            .toolbar {
                ToolbarItemGroup(placement: .primaryAction) {
                    Button("SSH") { showingSSHSheet = true }
                    Button("Importar .conf") { showingImportSheet = true }
                }
            }
            .sheet(isPresented: $showingImportSheet) { importWireGuardSheet }
            .sheet(isPresented: $showingSSHSheet) { sshProfileSheet }
        }
    }

    private var statusSection: some View {
        Section("Estado del Motor Nativo") {
            HStack {
                Text("Estado actual")
                Spacer()
                Text(viewModel.tunnelState.rawValue)
                    .font(.caption.monospaced().bold())
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background(Color.secondary.opacity(0.16))
                    .clipShape(Capsule())
            }
            Text(viewModel.statusBannerMessage)
                .font(.footnote)
                .foregroundStyle(.secondary)

            HStack(spacing: 12) {
                Button("Conectar Túnel") {
                    Task { await viewModel.connectSelectedProfile() }
                }
                .buttonStyle(.borderedProminent)
                .disabled(viewModel.profiles.isEmpty)

                Button("Desconectar") {
                    Task { await viewModel.disconnectActiveTunnel() }
                }
                .buttonStyle(.bordered)
            }
        }
    }

    /// Estado de la VPN: detalles del perfil activo y capacidades verificadas.
    private var vpnDetailSection: some View {
        Section("Estado de la VPN (extensión / proxy)") {
            if let profile = viewModel.selectedProfile {
                LabeledContent("Servidor", value: "\(profile.host):\(profile.port)")
                LabeledContent("Protocolo", value: profile.tunnelProtocol.rawValue)
                if let wg = profile.wireguard {
                    LabeledContent(
                        "AllowedIPs / rutas incluidas",
                        value: profile.includedRoutes.isEmpty ? "—" : profile.includedRoutes.joined(separator: ", ")
                    )
                    LabeledContent("DNS del perfil", value: wg.dnsServers?.joined(separator: ", ") ?? "—")
                }
            } else {
                Text("Sin perfil seleccionado.").font(.footnote).foregroundStyle(.secondary)
            }
            LabeledContent("Estado VPN", value: viewModel.tunnelState.rawValue)
            LabeledContent("Handshake del peer", value: viewModel.capabilityMatrix.wireguardHandshake ? "VERIFICADO" : "NO")
            LabeledContent(
                "RX/TX del peer",
                value: "RX +\(viewModel.capabilityMatrix.wireguardRXDeltaBytes) B / TX +\(viewModel.capabilityMatrix.wireguardTXDeltaBytes) B"
            )
        }
    }

    /// Red subyacente (clasificador rev. 2): familias y dimensiones separadas.
    private var underlyingNetworkSection: some View {
        Section("Red Subyacente (Clasificador rev. 2)") {
            if let result = viewModel.underlyingNetwork {
                familyRows("IPv4", result.ipv4)
                familyRows("IPv6", result.ipv6)
                Text("El estado VPN (\(result.vpnTunnelState)) se reporta por separado y no altera esta clasificación.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                Text("Sin clasificación previa. Configure sus destinos de sonda y ejecute el clasificador.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            Button("Ejecutar clasificador de red subyacente") {
                Task { await viewModel.runConnectivityClassification() }
            }
            .buttonStyle(.bordered)
        }
    }

    @ViewBuilder
    private func familyRows(_ label: String, _ report: JaroFamilyReport) -> some View {
        LabeledContent("\(label) — Clase", value: report.classification.rawValue)
        LabeledContent("\(label) — Capa IP", value: report.ipLayer.rawValue)
        LabeledContent("\(label) — DNS", value: report.dnsStatus.rawValue)
        LabeledContent("\(label) — HTTPS", value: report.httpsStatus.rawValue)
        LabeledContent("\(label) — Portal cautivo", value: report.portalStatus.rawValue)
    }

    /// Configuración de sondas del usuario (sin valores por defecto externos).
    private var probeConfigSection: some View {
        Section("Destinos de Sonda (configurados por usted)") {
            TextField("Resolvers DNS (IP separadas por coma)", text: $probeResolversInput)
                .jaroNoAutoCase()
            TextField("Nombre DNS a consultar", text: $probeQueryNameInput)
                .jaroNoAutoCase()
            TextField("URLs HTTPS (separadas por coma)", text: $probeHttpsInput)
                .jaroNoAutoCase()
            Button("Guardar destinos de sonda") {
                viewModel.saveProbeConfig(JaroProbeUserConfig(
                    dnsResolvers: splitList(probeResolversInput),
                    dnsQueryName: probeQueryNameInput.trimmingCharacters(in: .whitespacesAndNewlines),
                    httpsURLs: splitList(probeHttpsInput)
                ))
            }
            .disabled(probeQueryNameInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            Text("Sin destinos configurados, DNS y HTTPS quedan NOT_PROBED y la clase máxima es IP_ONLY. Ninguna sonda usa URLs públicas por defecto.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    private func splitList(_ value: String) -> [String] {
        value.split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
    }

    private var profilesSection: some View {
        Section("Perfiles Autorizados (.jaroprofile)") {
            if viewModel.profiles.isEmpty {
                Text("Sin servidores remotos registrados. Añade tu propio servidor SSH o WireGuard.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(viewModel.profiles) { profile in
                    HStack {
                        VStack(alignment: .leading, spacing: 3) {
                            Text(profile.displayName).font(.headline)
                            Text("\(profile.tunnelProtocol.rawValue) • \(profile.host):\(profile.port)")
                                .font(.caption.monospaced())
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        if viewModel.selectedProfileId == profile.profileId {
                            Image(systemName: "checkmark.circle.fill")
                        }
                    }
                    .contentShape(Rectangle())
                    .onTapGesture { viewModel.selectedProfileId = profile.profileId }
                }
            }
        }
    }

    private var costPolicySection: some View {
        Section("Modo de Operación y Red") {
            Toggle("Modo Standalone (Proxy Local sin extensión VPN)", isOn: $viewModel.isStandaloneMode)
            Toggle("Permitir redes medidas / datos móviles", isOn: $viewModel.allowExpensivePaths)
            Toggle("Marcar Wi-Fi actual como medido (Hotspot)", isOn: $viewModel.userMarkedMetered)
        }
    }

    private var telemetryAndCapabilitiesSection: some View {
        Section("Diagnóstico Real y Estadísticas RX/TX") {
            HStack {
                Text("RX: \(viewModel.trafficStats.rxBytes) B")
                Spacer()
                Text("TX: \(viewModel.trafficStats.txBytes) B")
            }
            .font(.caption.monospaced())
            LabeledContent("Proxy Local (SOCKS5 + CONNECT)", value: viewModel.capabilityMatrix.localProxyListening ? "ACTIVO" : "INACTIVO")
            LabeledContent("Sesión SSHv2 (Clave + SHA256)", value: viewModel.capabilityMatrix.sshAuthenticatedSession ? "VERIFICADA" : "NO")
            LabeledContent("Handshake WireGuard", value: viewModel.capabilityMatrix.wireguardHandshake ? "VERIFICADO" : "NO")
            LabeledContent("DNS del perfil", value: viewModel.capabilityMatrix.wireguardDNSConfigured ? "CONFIGURADO" : "NO")
            LabeledContent("Resolución DNS", value: viewModel.capabilityMatrix.wireguardDNSResolutionVerified ? "RESPUESTA OBSERVADA" : "NO VERIFICADA")
            LabeledContent(
                "Delta del peer WireGuard",
                value: "RX +\(viewModel.capabilityMatrix.wireguardRXDeltaBytes) B / TX +\(viewModel.capabilityMatrix.wireguardTXDeltaBytes) B"
            )
            LabeledContent(
                "Salida HTTPS por Túnel",
                value: (viewModel.capabilityMatrix.sshVerifiedHTTPS || viewModel.capabilityMatrix.wireguardVerifiedHTTPS)
                    ? "VERIFICADA" : "PENDIENTE"
            )
            #if canImport(NetworkExtension)
            TextField("URL HTTPS propia (https://IP literal con ruta AllowedIPs)", text: $httpsProbeURL)
                .jaroNoAutoCase()
            Button("Verificar Salida HTTPS Real por el Túnel") {
                Task { await viewModel.requestExtensionHTTPSVerification(probeURLString: httpsProbeURL) }
            }
            .disabled(httpsProbeURL.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            TextField("Nombre DNS propio/autorizado para consultar", text: $dnsQueryName)
                .jaroNoAutoCase()
            Button("Probar resolución DNS configurada") {
                Task { await viewModel.requestExtensionDNSVerification(queryName: dnsQueryName) }
            }
            .disabled(dnsQueryName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            Text("La consulta DNS usa el resolver de iOS tras instalar los ajustes del túnel. Una respuesta no demuestra por sí sola ausencia de fugas. La prueba HTTPS de WireGuard exige IP literal cubierta por AllowedIPs y deltas RX/TX del peer.")
                .font(.caption)
                .foregroundStyle(.secondary)
            #endif
        }
    }

    private var logsSection: some View {
        Section("Registros Redactados (< 15 MB Ring Buffer)") {
            if viewModel.recentLogs.isEmpty {
                Text("Sin eventos registrados.").font(.caption).foregroundStyle(.secondary)
            } else {
                ForEach(viewModel.recentLogs, id: \.self) { line in
                    Text(line).font(.system(size: 11, design: .monospaced))
                }
            }
        }
    }

    private var carrierSeparationInfoSection: some View {
        Section("Aviso Técnico — Operador Móvil vs. Túnel JARO") {
            Text(
                "Los motores WireGuard y SSH/SOCKS5 de JARO WPF operan exclusivamente sobre conectividad IP legítima y autorizada. " +
                "En redes móviles sin saldo (ej. Tigo Colombia), los canales oficiales gratuitos del operador están restringidos a portales propios de autogestión y recarga; JARO no evade cobros ni suplanta dominios."
            )
            .font(.caption)
            .foregroundStyle(.secondary)
        }
    }

    private var importWireGuardSheet: some View {
        NavigationStack {
            Form {
                TextField("ID del perfil (ej. wg-propio-01)", text: $wgProfileIdInput)
                    .jaroNoAutoCase()
                TextField("Nombre visible", text: $wgDisplayNameInput)
                TextEditor(text: $wgConfTextInput)
                    .frame(minHeight: 180)
                    .font(.caption.monospaced())
                Section("Consentimiento explícito") {
                    Toggle("Autorizar DNS= del perfil (cambia el DNS del sistema)", isOn: $allowDNSOverride)
                    Toggle("Autorizar full tunnel dual-stack (0.0.0.0/0 + ::/0 e includeAllNetworks de iOS)", isOn: $allowFullTunnel)
                    Text("Full tunnel requiere ambas rutas por defecto, direcciones IPv4 e IPv6 y consentimiento DNS. Al aceptarlo, iOS enruta la mayoría del tráfico por la VPN y descarta tráfico mientras el proveedor no está Connected; Apple conserva excepciones de control de red, portal cautivo, ciertos servicios celulares y dispositivos complementarios. No es una garantía de que cada paquete del sistema quede dentro del túnel.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .navigationTitle("Importar WireGuard .conf")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancelar") { showingImportSheet = false }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Guardar en Keychain") {
                        viewModel.importWireGuardConfiguration(
                            profileId: wgProfileIdInput,
                            displayName: wgDisplayNameInput.isEmpty ? wgProfileIdInput : wgDisplayNameInput,
                            confText: wgConfTextInput,
                            authorized: true,
                            allowDNSOverride: allowDNSOverride,
                            allowFullTunnel: allowFullTunnel
                        )
                        wgConfTextInput = ""
                        allowDNSOverride = false
                        allowFullTunnel = false
                        showingImportSheet = false
                    }
                    .disabled(wgProfileIdInput.isEmpty || wgConfTextInput.isEmpty)
                }
            }
        }
    }

    private var sshProfileSheet: some View {
        SSHProfileSetupSheet { values in
            viewModel.importSSHProfile(
                profileId: values.profileId,
                displayName: values.displayName,
                host: values.host,
                port: values.port,
                username: values.username,
                fingerprint: values.fingerprint,
                privateKeySeedBase64: values.privateSeedBase64
            )
            showingSSHSheet = false
        }
    }
}

private struct SSHProfileValues {
    let profileId: String
    let displayName: String
    let host: String
    let port: Int
    let username: String
    let fingerprint: String
    let privateSeedBase64: String
}

private struct SSHProfileSetupSheet: View {
    let onSave: (SSHProfileValues) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var profileId = ""
    @State private var displayName = ""
    @State private var host = ""
    @State private var port = "22"
    @State private var username = ""
    @State private var fingerprint = ""
    @State private var privateSeedBase64 = ""
    @State private var publicKeyLine = ""
    @State private var generated = false

    var body: some View {
        NavigationStack {
            Form {
                Section("Servidor SSH") {
                    TextField("ID único", text: $profileId).jaroNoAutoCase()
                    TextField("Nombre", text: $displayName)
                    TextField("IP o dominio", text: $host).jaroNoAutoCase()
                    TextField("Puerto", text: $port).jaroNumericInput()
                    TextField("Usuario Linux", text: $username).jaroNoAutoCase()
                    TextField("Huella SHA256 del servidor", text: $fingerprint).jaroNoAutoCase()
                }

                Section("Clave de acceso JARO") {
                    if generated {
                        Text("Clave Ed25519 creada en este iPhone. La privada se guardará en Keychain.")
                            .font(.footnote)
                        Text("Clave pública para añadir a ~/.ssh/authorized_keys:")
                            .font(.caption)
                        Text(publicKeyLine)
                            .font(.system(size: 11, design: .monospaced))
                            .textSelection(.enabled)
                        Button("Copiar clave pública") {
                            #if canImport(UIKit)
                            UIPasteboard.general.string = publicKeyLine
                            #endif
                        }
                    } else {
                        Button("Generar clave segura en este iPhone") {
                            let key = Curve25519.Signing.PrivateKey()
                            privateSeedBase64 = key.rawRepresentation.base64EncodedString()
                            publicKeyLine = Self.openSSHEd25519PublicKey(key.publicKey.rawRepresentation)
                            generated = true
                        }
                    }
                    Text("No compartas ni envíes la clave privada. Solo debes copiar la línea pública al archivo authorized_keys del PC.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }

                Section {
                    Button("Guardar perfil SSH") {
                        guard let portNumber = Int(port) else { return }
                        onSave(SSHProfileValues(
                            profileId: profileId,
                            displayName: displayName,
                            host: host,
                            port: portNumber,
                            username: username,
                            fingerprint: fingerprint,
                            privateSeedBase64: privateSeedBase64
                        ))
                    }
                    .disabled(!generated || profileId.isEmpty || host.isEmpty || username.isEmpty || fingerprint.isEmpty || Int(port) == nil)
                }
            }
            .navigationTitle("Configurar SSH")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancelar") { dismiss() }
                }
            }
        }
    }

    private static func openSSHEd25519PublicKey(_ rawPublicKey: Data) -> String {
        func appendUInt32(_ value: UInt32, to data: inout Data) {
            data.append(UInt8((value >> 24) & 0xff))
            data.append(UInt8((value >> 16) & 0xff))
            data.append(UInt8((value >> 8) & 0xff))
            data.append(UInt8(value & 0xff))
        }
        func appendSSHString(_ value: Data, to data: inout Data) {
            appendUInt32(UInt32(value.count), to: &data)
            data.append(value)
        }
        let algorithm = Data("ssh-ed25519".utf8)
        var blob = Data()
        appendSSHString(algorithm, to: &blob)
        appendSSHString(rawPublicKey, to: &blob)
        return "ssh-ed25519 \(blob.base64EncodedString()) jaro-wpf-iphone"
    }
}

private extension View {
    @ViewBuilder
    func jaroNoAutoCase() -> some View {
        #if canImport(UIKit)
        self.textInputAutocapitalization(.never).autocorrectionDisabled()
        #else
        self
        #endif
    }

    @ViewBuilder
    func jaroNumericInput() -> some View {
        #if canImport(UIKit)
        self.keyboardType(.numberPad)
        #else
        self
        #endif
    }
}
#endif
