// JARO WPF — Phase 6 Native iOS Tunnel Engine
// Module: JaroApp (SwiftUI Application Entry Point)
// Organization: JARO COMPLEMETS

#if canImport(SwiftUI)
import SwiftUI

// `@main` solo en builds de app (XcodeGen define JARO_APP_ENTRY). En
// `swift test` el runner de XCTest aporta el _main y evitamos el símbolo
// duplicado cuando JaroApp se enlaza como dependencia del test target.
#if JARO_APP_ENTRY
@main
public struct JaroWPFApp: App {
    @StateObject private var viewModel = JaroDashboardViewModel()

    public init() {}

    public var body: some Scene {
        WindowGroup {
            JaroMainView(viewModel: viewModel)
        }
    }
}
#endif
#endif
