// JARO WPF — Phase 6 Native iOS Tunnel Engine
// Module: JaroApp (SwiftUI Main View — Profiles, Tunnel Telemetry, Diagnostics & Tigo Info Separation)
// Organization: JARO COMPLEMETS

#if canImport(SwiftUI)
import JaroCore
import SwiftUI

public struct JaroMainView: View {
    @ObservedObject private var viewModel: JaroDashboardViewModel
    @State private var showingImportSheet = false
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
                ToolbarItem(placement: .primaryAction) {
                    Button("Importar .conf") {
                        showingImportSheet = true
                    }
                }
            }
            .sheet(isPresented: $showingImportSheet) {
                importWireGuardSheet
            }
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
                Text("Sin servidores remotos registrados (REMOTE_SERVER_REQUIRED). Ningún servidor ni credencial viene preinstalado.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(viewModel.profiles) { profile in
                    HStack {
                        VStack(alignment: .leading, spacing: 3) {
                            Text(profile.displayName)
                                .font(.headline)
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
                    .onTapGesture {
                        viewModel.selectedProfileId = profile.profileId
                    }
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
                Text("Sin eventos registrados.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(viewModel.recentLogs, id: \.self) { line in
                    Text(line)
                        .font(.system(size: 11, design: .monospaced))
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
                #if os(iOS)
                TextField("ID del perfil (ej. wg-propio-01)", text: $wgProfileIdInput)
                    .textInputAutocapitalization(.never)
                #else
                TextField("ID del perfil (ej. wg-propio-01)", text: $wgProfileIdInput)
                #endif
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
}
#endif
