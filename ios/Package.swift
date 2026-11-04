// swift-tools-version: 5.9
// JARO WPF — Phase 6 Native iOS Tunnel Engine
// Organization: JARO COMPLEMETS
// Project: JARO WPF

import PackageDescription

// Set JARO_ENABLE_WIREGUARDKIT=1 in Xcode / build environment once WireGuardGoBridgeiOS (`libwg-go.a`)
// has been built via the External Build System target documented in `project.yml`.
let enableWireGuardKit = Context.environment["JARO_ENABLE_WIREGUARDKIT"] == "1"

var packageDependencies: [Package.Dependency] = [
    // SwiftNIO core event loop & ByteBuffer primitives (Apache-2.0)
    .package(url: "https://github.com/apple/swift-nio.git", from: "2.65.0"),
    // Apple Network.framework integration (`NIOTSConnectionBootstrap`) for iOS battery/memory efficiency (Apache-2.0)
    .package(url: "https://github.com/apple/swift-nio-transport-services.git", from: "1.21.0"),
    // In-process SSHv2 protocol & DirectTCPIP channels without spawning external binaries (Apache-2.0)
    .package(url: "https://github.com/apple/swift-nio-ssh.git", "0.9.0"..<"0.12.0"),
    // Cross-platform Swift Crypto primitives (Curve25519, Ed25519, SHA256) (Apache-2.0)
    .package(url: "https://github.com/apple/swift-crypto.git", from: "3.4.0"),
]

var tunnelEngineDependencies: [Target.Dependency] = [
    "JaroCore",
    "JaroSecurity",
    "JaroProfiles",
    .product(name: "NIOCore", package: "swift-nio"),
    .product(name: "NIOPosix", package: "swift-nio"),
    .product(name: "NIOTransportServices", package: "swift-nio-transport-services"),
    .product(name: "NIOSSH", package: "swift-nio-ssh"),
    .product(name: "Crypto", package: "swift-crypto"),
]

if enableWireGuardKit {
    // Official WireGuardKit (MIT License — WireGuard is a registered trademark of Jason A. Donenfeld;
    // JARO WPF uses independent "JARO WPF" / "JARO COMPLEMETS" branding).
    packageDependencies.append(
        .package(url: "https://git.zx2c4.com/wireguard-apple", from: "1.0.16")
    )
    tunnelEngineDependencies.append(
        .product(name: "WireGuardKit", package: "wireguard-apple")
    )
}

let package = Package(
    name: "JaroIOS",
    platforms: [
        .iOS(.v16),
        .macOS(.v13),
    ],
    products: [
        .library(name: "JaroCore", targets: ["JaroCore"]),
        .library(name: "JaroSecurity", targets: ["JaroSecurity"]),
        .library(name: "JaroProfiles", targets: ["JaroProfiles"]),
        .library(name: "JaroTunnelEngine", targets: ["JaroTunnelEngine"]),
        .library(name: "JaroDiagnostics", targets: ["JaroDiagnostics"]),
        .library(name: "JaroPacketTunnel", targets: ["JaroPacketTunnel"]),
        .library(name: "JaroAppUI", targets: ["JaroApp"]),
    ],
    dependencies: packageDependencies,
    targets: [
        // 1. JaroCore: Shared domain models, secret redaction, ring log buffer (<15 MB safe), backoff reconnector
        .target(
            name: "JaroCore",
            dependencies: [],
            path: "Sources/JaroCore"
        ),
        // 2. JaroSecurity: Keychain vault (`Security.framework`), Curve25519/Ed25519/SHA256 & X.509 TLS validators
        .target(
            name: "JaroSecurity",
            dependencies: [
                "JaroCore",
                .product(name: "Crypto", package: "swift-crypto"),
            ],
            path: "Sources/JaroSecurity"
        ),
        // 3. JaroProfiles: `.jaroprofile` v1.0 & WireGuard `.conf` importer/exporter (zero plaintext secrets)
        .target(
            name: "JaroProfiles",
            dependencies: [
                "JaroCore",
                "JaroSecurity",
            ],
            path: "Sources/JaroProfiles"
        ),
        // 4. JaroTunnelEngine: Native WireGuard (`WireGuardKit`), Native SSH (`SwiftNIOSSH`), Dual SOCKS5 + HTTP CONNECT
        .target(
            name: "JaroTunnelEngine",
            dependencies: tunnelEngineDependencies,
            path: "Sources/JaroTunnelEngine"
        ),
        // 5. JaroDiagnostics: `NWPathMonitor` cost/metered guard & HTTPS egress verifier over tunnel
        .target(
            name: "JaroDiagnostics",
            dependencies: [
                "JaroCore",
                "JaroSecurity",
                "JaroProfiles",
            ],
            path: "Sources/JaroDiagnostics"
        ),
        // 6. JaroPacketTunnel: `NEPacketTunnelProvider` VPN system extension (`<= 15 MB` jetsam ceiling)
        .target(
            name: "JaroPacketTunnel",
            dependencies: [
                "JaroCore",
                "JaroSecurity",
                "JaroProfiles",
                "JaroTunnelEngine",
                "JaroDiagnostics",
            ],
            path: "Sources/JaroPacketTunnel",
            exclude: ["Info.plist"]
        ),
        // 7. JaroApp: SwiftUI interface, `NETunnelProviderManager` controller, diagnostics & Tigo info separation
        .target(
            name: "JaroApp",
            dependencies: [
                "JaroCore",
                "JaroSecurity",
                "JaroProfiles",
                "JaroDiagnostics",
                "JaroTunnelEngine",
            ],
            path: "Sources/JaroApp",
            exclude: ["Info.plist"]
        ),
        // Unit tests for core models, profile validation, secret redaction & backoff reconnector
        .testTarget(
            name: "JaroCoreTests",
            dependencies: [
                "JaroCore",
                "JaroSecurity",
                "JaroProfiles",
            ],
            path: "Tests/JaroCoreTests"
        ),
    ]
)
