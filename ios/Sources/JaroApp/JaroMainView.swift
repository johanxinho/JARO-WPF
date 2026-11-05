// JARO WPF — Phase 6 Native iOS Tunnel Engine
// Module: JaroApp (SwiftUI Main View — Profiles, Tunnel Telemetry, Diagnostics & Tigo Info Separation)
// Organization: JARO COMPLEMETS

#if canImport(SwiftUI)
import JaroCore
import SwiftUI
import CryptoKit

public struct JaroMainView: View {
    @ObservedObject private var viewModel: JaroDashboardViewModel
    @State private var showingImportSheet = false
    @State private var showingSSHSheet = false
    @State private var wgProfileIdInput = ""
    @State private var wgDisplayNameInput = ""
    @State private var wgConfTextInput = ""

    public init(viewModel: JaroDashboardViewModel) {
        self.viewModel = viewModel
    }

    public var body: some View {
        NavigationStack {
            List {
                statusSection
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
            LabeledContent(
                "Salida HTTPS por Túnel",
                value: (viewModel.capabilityMatrix.sshVerifiedHTTPS || viewModel.capabilityMatrix.wireguardVerifiedHTTPS)
                    ? "VERIFICADA" : "PENDIENTE"
            )
            #if canImport(NetworkExtension)
            Button("Verificar Salida HTTPS Real por el Túnel") {
                Task { await viewModel.requestExtensionHTTPSVerification() }
            }
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
                    .textInputAutocapitalization(.never)
                TextField("Nombre visible", text: $wgDisplayNameInput)
                TextEditor(text: $wgConfTextInput)
                    .frame(minHeight: 180)
                    .font(.caption.monospaced())
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
                            authorized: true
                        )
                        wgConfTextInput = ""
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
    @State private var profileId = "ssh-pc-casa"
    @State private var displayName = "Mi PC Linux"
    @State private var host = "192.168.1.242"
    @State private var port = "22"
    @State private var username = "johanxinho"
    @State private var fingerprint = "SHA256:nnWv8FwZTu1qXxwQ9XBJsnAkLPIQDmM2EqxrhyHf1JM"
    @State private var privateSeedBase64 = ""
    @State private var publicKeyLine = ""
    @State private var generated = false

    var body: some View {
        NavigationStack {
            Form {
                Section("Servidor SSH") {
                    TextField("ID único", text: $profileId).textInputAutocapitalization(.never)
                    TextField("Nombre", text: $displayName)
                    TextField("IP o dominio", text: $host).textInputAutocapitalization(.never).autocorrectionDisabled()
                    TextField("Puerto", text: $port).keyboardType(.numberPad)
                    TextField("Usuario Linux", text: $username).textInputAutocapitalization(.never).autocorrectionDisabled()
                    TextField("Huella SHA256 del servidor", text: $fingerprint).textInputAutocapitalization(.never).autocorrectionDisabled()
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
#endif
