// JARO WPF — Phase 6 Native iOS Tunnel Engine
// Module: JaroApp (SwiftUI Application Entry Point)
// Organization: JARO COMPLEMETS

#if canImport(SwiftUI)
import SwiftUI

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
