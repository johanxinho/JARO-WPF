// JARO WPF — Phase 6 Native iOS Tunnel Engine
// Module: JaroTunnelEngine (In-Process Native SSHv2 Engine via SwiftNIO SSH — Priority C)
// Organization: JARO COMPLEMETS

import Crypto
import Foundation
import JaroCore
import JaroProfiles
import JaroSecurity
import NIOCore
import NIOPosix
import NIOSSH
#if canImport(NIOTransportServices)
import NIOTransportServices
#endif

public enum JaroSSHEngineError: Error, LocalizedError {
    case missingSSHProfileSection
    case unsupportedPrivateKeyMaterial
    case sessionNotConnected
    case invalidDirectTCPIPChannelType
    case authenticationRejected

    public var errorDescription: String? {
        switch self {
        case .missingSSHProfileSection:
            return "Profile does not contain a valid ssh_socks5 configuration block"
        case .unsupportedPrivateKeyMaterial:
            return "SSH private key in Keychain must be raw 32-byte Base64 Ed25519 seed or P-256 ANSI X9.63/raw key"
        case .sessionNotConnected:
            return "Native SwiftNIO SSH session is not currently active"
        case .invalidDirectTCPIPChannelType:
            return "SSH server returned an unexpected channel type instead of direct-tcpip"
        case .authenticationRejected:
            return "SSH public-key authentication was rejected by the remote server"
        }
    }
}

/// Strictly validates the SSH server's host key against the profile's pinned `SHA256:...` fingerprint.
/// Never accepts `AcceptAllHostKeysDelegate` or Trust-On-First-Use (TOFU).
final class JaroPinnedHostKeyDelegate: NIOSSHClientServerAuthenticationDelegate {
    private let expectedSHA256: String
    private let logBuffer: JaroRingLogBuffer

    init(expectedSHA256: String, logBuffer: JaroRingLogBuffer) {
        self.expectedSHA256 = expectedSHA256
        self.logBuffer = logBuffer
    }

    func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
        let openSSHLine = String(openSSHPublicKey: hostKey)
        do {
            try JaroCryptoValidators.verifyPinnedHostKey(
                openSSHPublicKeyLine: openSSHLine,
                expectedSHA256: expectedSHA256
            )
            logBuffer.append(
                level: "INFO",
                component: "JaroPinnedHostKeyDelegate",
                message: "Verified pinned SSH host key (\(expectedSHA256))"
            )
            validationCompletePromise.succeed(())
        } catch {
            logBuffer.append(
                level: "ERROR",
                component: "JaroPinnedHostKeyDelegate",
                message: "Rejected untrusted SSH host key: \(error.localizedDescription)"
            )
            validationCompletePromise.fail(error)
        }
    }
}

/// Strictly offers a single Ed25519 or P-256 public-key authentication attempt loaded from iOS Keychain.
/// Never sends passwords or keyboard-interactive responses.
final class JaroPrivateKeyUserAuthDelegate: NIOSSHClientUserAuthenticationDelegate {
    private let username: String
    private let privateKey: NIOSSHPrivateKey
    private var didOfferOnce = false

    init(username: String, privateKey: NIOSSHPrivateKey) {
        self.username = username
        self.privateKey = privateKey
    }

    func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        guard !didOfferOnce, availableMethods.contains(.publicKey) else {
            nextChallengePromise.succeed(nil)
            return
        }
        didOfferOnce = true
        nextChallengePromise.succeed(
            NIOSSHUserAuthenticationOffer(
                username: username,
                serviceName: "",
                offer: .privateKey(.init(privateKey: privateKey))
            )
        )
    }
}

/// Captures fatal SSH pipeline errors into the bounded ring log buffer without leaking credentials.
final class JaroSSHErrorHandler: ChannelInboundHandler {
    typealias InboundIn = Any
    private let logBuffer: JaroRingLogBuffer

    init(logBuffer: JaroRingLogBuffer) {
        self.logBuffer = logBuffer
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        logBuffer.append(
            level: "ERROR",
            component: "JaroNativeSSHEngine",
            message: "SSH pipeline error: \(error.localizedDescription)"
        )
        context.close(promise: nil)
    }
}

/// Native in-process SSHv2 engine built on Apple's `SwiftNIO SSH` (`0.15.0+`) and `NIOTransportServices`.
/// Runs on a single-thread event loop inside `NEPacketTunnelProvider` (`< 15 MB` RAM) without spawning `/usr/bin/ssh`.
public final class JaroNativeSSHEngine: @unchecked Sendable {
    private let lock = NSLock()
    private let logBuffer: JaroRingLogBuffer
    private var eventLoopGroup: EventLoopGroup?
    private var sessionChannel: Channel?

    public init(logBuffer: JaroRingLogBuffer) {
        self.logBuffer = logBuffer
    }

    /// True ONLY when the underlying TCP/NWConnection channel is genuinely open and active (no cached flags).
    public var isSessionActive: Bool {
        lock.lock()
        let ch = sessionChannel
        lock.unlock()
        return ch?.isActive ?? false
    }

    public func connect(
        profile: JaroPortableProfile,
        secretStore: JaroSecretStoreProtocol,
        connectTimeoutSeconds: Int64 = 10
    ) async throws {
        try await disconnect()
        try JaroProfileManager.validateProfile(profile)
        guard let sshSection = profile.sshSocks5 else {
            throw JaroSSHEngineError.missingSSHProfileSection
        }

        let keyData = try secretStore.loadSecret(forURI: profile.cryptoReferences.keychainSecretRef)
        let nioPrivateKey = try Self.parseSSHPrivateKey(from: keyData)

        let hostKeyDelegate = JaroPinnedHostKeyDelegate(
            expectedSHA256: sshSection.pinnedHostKeySHA256,
            logBuffer: logBuffer
        )
        let userAuthDelegate = JaroPrivateKeyUserAuthDelegate(
            username: sshSection.username,
            privateKey: nioPrivateKey
        )

        #if canImport(NIOTransportServices)
        let group: EventLoopGroup = NIOTSEventLoopGroup(loopCount: 1)
        let bootstrap = NIOTSConnectionBootstrap(group: group)
            .connectTimeout(.seconds(connectTimeoutSeconds))
            .channelInitializer { [logBuffer] channel in
                let sshHandler = NIOSSHHandler(
                    role: .client(
                        .init(
                            userAuthDelegate: userAuthDelegate,
                            serverAuthDelegate: hostKeyDelegate
                        )
                    ),
                    allocator: channel.allocator,
                    inboundChildChannelInitializer: nil
                )
                return channel.pipeline.addHandlers([sshHandler, JaroSSHErrorHandler(logBuffer: logBuffer)])
            }
        #else
        let group: EventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let bootstrap = ClientBootstrap(group: group)
            .connectTimeout(.seconds(connectTimeoutSeconds))
            .channelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: 1)
            .channelInitializer { [logBuffer] channel in
                let sshHandler = NIOSSHHandler(
                    role: .client(
                        .init(
                            userAuthDelegate: userAuthDelegate,
                            serverAuthDelegate: hostKeyDelegate
                        )
                    ),
                    allocator: channel.allocator,
                    inboundChildChannelInitializer: nil
                )
                return channel.pipeline.addHandlers([sshHandler, JaroSSHErrorHandler(logBuffer: logBuffer)])
            }
        #endif

        do {
            let channel = try await bootstrap.connect(host: profile.host, port: profile.port).get()
            lock.lock()
            self.eventLoopGroup = group
            self.sessionChannel = channel
            lock.unlock()
            logBuffer.append(
                level: "INFO",
                component: "JaroNativeSSHEngine",
                message: "Connected SSHv2 transport to \(profile.host):\(profile.port) as \(sshSection.username)"
            )
        } catch {
            try? await group.shutdownGracefully()
            throw error
        }
    }

    /// Opens an SSH `direct-tcpip` child `Channel` multiplexed over the active SSHv2 connection.
    public func openDirectTCPIPChannel(
        targetHost: String,
        targetPort: Int,
        originatorAddress: SocketAddress?,
        childChannelInitializer: @escaping @Sendable (Channel) -> EventLoopFuture<Void>
    ) -> EventLoopFuture<Channel> {
        lock.lock()
        let activeChannel = sessionChannel
        lock.unlock()

        guard let session = activeChannel, session.isActive else {
            let loop = MultiThreadedEventLoopGroup.singleton.next()
            return loop.makeFailedFuture(JaroSSHEngineError.sessionNotConnected)
        }

        let fallbackOrigin = try? SocketAddress(ipAddress: "127.0.0.1", port: 0)
        guard let origin = originatorAddress ?? session.localAddress ?? fallbackOrigin else {
            return session.eventLoop.makeFailedFuture(JaroSSHEngineError.sessionNotConnected)
        }

        return session.pipeline.handler(type: NIOSSHHandler.self).flatMap { sshHandler in
            let promise = session.eventLoop.makePromise(of: Channel.self)
            let directSpec = SSHChannelType.DirectTCPIP(
                targetHost: targetHost,
                targetPort: targetPort,
                originatorAddress: origin
            )
            sshHandler.createChannel(promise, channelType: .directTCPIP(directSpec)) { childChannel, channelType in
                guard case .directTCPIP = channelType else {
                    return childChannel.eventLoop.makeFailedFuture(JaroSSHEngineError.invalidDirectTCPIPChannelType)
                }
                return childChannelInitializer(childChannel)
            }
            return promise.futureResult
        }
    }

    public func disconnect() async throws {
        lock.lock()
        let ch = sessionChannel
        let grp = eventLoopGroup
        sessionChannel = nil
        eventLoopGroup = nil
        lock.unlock()

        if let ch = ch, ch.isActive {
            try? await ch.close().get()
        }
        if let grp = grp {
            try await grp.shutdownGracefully()
        }
    }

    /// Parses Keychain secret material into `NIOSSHPrivateKey`:
    /// - Raw 32-byte Ed25519 seed (or Base64-encoded 32-byte Ed25519 seed)
    /// - Raw 32-byte P-256 key (when prefixed with `"p256:"`)
    public static func parseSSHPrivateKey(from secretData: Data) throws -> NIOSSHPrivateKey {
        if secretData.count == 32 {
            let edKey = try Curve25519.Signing.PrivateKey(rawRepresentation: secretData)
            return NIOSSHPrivateKey(ed25519Key: edKey)
        }
        if let text = String(data: secretData, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines) {
            if text.hasPrefix("p256:") {
                let rawB64 = String(text.dropFirst("p256:".count))
                guard let decoded = Data(base64Encoded: rawB64) else {
                    throw JaroSSHEngineError.unsupportedPrivateKeyMaterial
                }
                let p256Key = try P256.Signing.PrivateKey(rawRepresentation: decoded)
                return NIOSSHPrivateKey(p256Key: p256Key)
            }
            let stripped = text.hasPrefix("ed25519:") ? String(text.dropFirst("ed25519:".count)) : text
            if let decoded = Data(base64Encoded: stripped), decoded.count == 32 {
                let edKey = try Curve25519.Signing.PrivateKey(rawRepresentation: decoded)
                return NIOSSHPrivateKey(ed25519Key: edKey)
            }
        }
        throw JaroSSHEngineError.unsupportedPrivateKeyMaterial
    }
}
