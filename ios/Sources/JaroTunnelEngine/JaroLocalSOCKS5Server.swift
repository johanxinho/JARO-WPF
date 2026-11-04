// JARO WPF — Phase 6 Native iOS Tunnel Engine
// Module: JaroTunnelEngine (Dual RFC 1928 SOCKS5 + RFC 9110 HTTP CONNECT Loopback Proxy — Priority D)
// Organization: JARO COMPLEMETS

import Foundation
import JaroCore
import NIOCore
import NIOPosix
import NIOSSH

public enum JaroLocalProxyError: Error, LocalizedError {
    case nonLoopbackBindForbidden(String)
    case unsupportedProxyFraming(UInt8)
    case invalidSOCKS5Header
    case invalidHTTPConnectHeader

    public var errorDescription: String? {
        switch self {
        case .nonLoopbackBindForbidden(let host):
            return "JaroLocalSOCKS5Server must bind exclusively to loopback, never \(host)"
        case .unsupportedProxyFraming(let byte):
            return String(format: "Unsupported initial proxy byte: 0x%02X", byte)
        case .invalidSOCKS5Header:
            return "Malformed RFC 1928 SOCKS5 greeting or CONNECT header"
        case .invalidHTTPConnectHeader:
            return "Malformed RFC 9110 HTTP CONNECT request header"
        }
    }
}

/// Thread-safe byte & stream counter shared between the local proxy listener and `NEPacketTunnelProvider` telemetry.
public final class JaroProxyTrafficAccumulator: @unchecked Sendable {
    private let lock = NSLock()
    private var rxBytes: UInt64 = 0
    private var txBytes: UInt64 = 0
    private var socks5Count: UInt64 = 0
    private var httpConnectCount: UInt64 = 0

    public init() {}

    public func recordTX(_ count: Int) {
        guard count > 0 else { return }
        lock.lock()
        txBytes &+= UInt64(count)
        lock.unlock()
    }

    public func recordRX(_ count: Int) {
        guard count > 0 else { return }
        lock.lock()
        rxBytes &+= UInt64(count)
        lock.unlock()
    }

    public func incrementSOCKS5() {
        lock.lock()
        socks5Count &+= 1
        lock.unlock()
    }

    public func incrementHTTPConnect() {
        lock.lock()
        httpConnectCount &+= 1
        lock.unlock()
    }

    public func snapshot() -> JaroTrafficStats {
        lock.lock()
        defer { lock.unlock() }
        return JaroTrafficStats(
            rxBytes: rxBytes,
            txBytes: txBytes,
            socks5Connections: socks5Count,
            httpConnectConnections: httpConnectCount
        )
    }
}

/// Bidirectional SwiftNIO relay handler translating between TCP `ByteBuffer` and `SSHChannelData` (`DirectTCPIP`).
final class JaroSSHDirectTCPIPGlueHandler: ChannelDuplexHandler {
    typealias InboundIn = Any
    typealias OutboundIn = Any
    typealias OutboundOut = Any

    private weak var partnerChannel: Channel?
    private let isSSHChannelSide: Bool
    private let accumulator: JaroProxyTrafficAccumulator

    init(partnerChannel: Channel?, isSSHChannelSide: Bool, accumulator: JaroProxyTrafficAccumulator) {
        self.partnerChannel = partnerChannel
        self.isSSHChannelSide = isSSHChannelSide
        self.accumulator = accumulator
    }

    func setPartner(_ partner: Channel) {
        self.partnerChannel = partner
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard let partner = partnerChannel, partner.isActive else {
            context.close(promise: nil)
            return
        }

        if isSSHChannelSide {
            // Inbound from SSH DirectTCPIP -> unwrap SSHChannelData -> write raw ByteBuffer to local app socket (RX)
            let sshData = unwrapInboundIn(data)
            if let channelData = sshData as? SSHChannelData,
               case .channel = channelData.type,
               case .byteBuffer(let buf) = channelData.data {
                accumulator.recordRX(buf.readableBytes)
                partner.writeAndFlush(buf, promise: nil)
            }
        } else {
            // Inbound from local app socket -> wrap ByteBuffer in SSHChannelData -> write to SSH DirectTCPIP (TX)
            if let buf = unwrapInboundIn(data) as? ByteBuffer {
                accumulator.recordTX(buf.readableBytes)
                let wrapped = SSHChannelData(type: .channel, data: .byteBuffer(buf))
                partner.writeAndFlush(wrapped, promise: nil)
            }
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        partnerChannel?.close(promise: nil)
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        partnerChannel?.close(promise: nil)
        context.close(promise: nil)
    }
}

/// Stateful proxy handshake handler supporting BOTH:
/// 1. `0x05`: RFC 1928 SOCKS5 (`NO AUTH`, `CONNECT` IPv4/Domain/IPv6) for SOCKS5-aware URLSessions / apps.
/// 2. `'C'`/`'c'`: RFC 9110 `HTTP CONNECT host:port HTTP/1.1` so iOS `NEProxySettings.httpsServer` can tunnel
///    system-wide HTTPS traffic into `JaroNativeSSHEngine`'s `DirectTCPIP` channel!
final class JaroDualProtocolHandshakeHandler: ChannelInboundHandler, RemovableChannelHandler {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private enum State {
        case awaitingFirstByte
        case socks5AwaitingConnectRequest
        case httpConnectAccumulatingHeader
        case connectingUpstream
    }

    private var state: State = .awaitingFirstByte
    private var cumulativeBuffer: ByteBuffer?
    private let sshEngine: JaroNativeSSHEngine
    private let localPort: Int
    private let accumulator: JaroProxyTrafficAccumulator
    private let logBuffer: JaroRingLogBuffer

    init(
        sshEngine: JaroNativeSSHEngine,
        localPort: Int,
        accumulator: JaroProxyTrafficAccumulator,
        logBuffer: JaroRingLogBuffer
    ) {
        self.sshEngine = sshEngine
        self.localPort = localPort
        self.accumulator = accumulator
        self.logBuffer = logBuffer
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var incoming = unwrapInboundIn(data)
        if cumulativeBuffer == nil {
            cumulativeBuffer = context.channel.allocator.buffer(capacity: incoming.readableBytes)
        }
        cumulativeBuffer?.writeBuffer(&incoming)
        processBufferedBytes(context: context)
    }

    private func processBufferedBytes(context: ChannelHandlerContext) {
        guard var buf = cumulativeBuffer, buf.readableBytes > 0 else { return }

        switch state {
        case .awaitingFirstByte:
            guard let firstByte = buf.getInteger(at: buf.readerIndex, as: UInt8.self) else { return }
            if firstByte == 0x05 {
                // RFC 1928 SOCKS5 Greeting: [VER=0x05, NMETHODS, METHODS...]
                guard buf.readableBytes >= 2,
                      let nMethods = buf.getInteger(at: buf.readerIndex + 1, as: UInt8.self) else {
                    return
                }
                let totalGreeting = 2 + Int(nMethods)
                guard buf.readableBytes >= totalGreeting else { return }
                _ = buf.readInteger(as: UInt8.self) // VER
                _ = buf.readInteger(as: UInt8.self) // NMETHODS
                guard let methodsSlice = buf.readBytes(length: Int(nMethods)) else { return }
                cumulativeBuffer = buf

                guard methodsSlice.contains(0x00) else {
                    var reject = context.channel.allocator.buffer(capacity: 2)
                    reject.writeBytes([0x05, 0xFF])
                    context.writeAndFlush(wrapOutboundOut(reject)).whenComplete { _ in
                        context.close(promise: nil)
                    }
                    return
                }

                accumulator.incrementSOCKS5()
                state = .socks5AwaitingConnectRequest
                var accept = context.channel.allocator.buffer(capacity: 2)
                accept.writeBytes([0x05, 0x00])
                context.writeAndFlush(wrapOutboundOut(accept), promise: nil)
                if buf.readableBytes > 0 {
                    processBufferedBytes(context: context)
                }

            } else if firstByte == 0x43 || firstByte == 0x63 {
                accumulator.incrementHTTPConnect()
                state = .httpConnectAccumulatingHeader
                processBufferedBytes(context: context)
            } else {
                logBuffer.append(
                    level: "WARN",
                    component: "JaroLocalSOCKS5Server",
                    message: String(format: "Rejected unknown proxy framing byte 0x%02X", firstByte)
                )
                context.close(promise: nil)
            }

        case .socks5AwaitingConnectRequest:
            // [VER=0x05, CMD=0x01, RSV=0x00, ATYP, DST.ADDR, DST.PORT]
            guard buf.readableBytes >= 4,
                  let cmd = buf.getInteger(at: buf.readerIndex + 1, as: UInt8.self),
                  let atyp = buf.getInteger(at: buf.readerIndex + 3, as: UInt8.self) else {
                return
            }
            guard cmd == 0x01 else {
                sendSOCKS5Reply(context: context, rep: 0x07)
                context.close(promise: nil)
                return
            }

            let targetHost: String
            let headerLen: Int
            switch atyp {
            case 0x01: // IPv4
                headerLen = 4 + 4 + 2
                guard buf.readableBytes >= headerLen,
                      let ipBytes = buf.getBytes(at: buf.readerIndex + 4, length: 4) else { return }
                targetHost = "\(ipBytes[0]).\(ipBytes[1]).\(ipBytes[2]).\(ipBytes[3])"
            case 0x03: // Domain
                guard buf.readableBytes >= 5,
                      let dLenU8 = buf.getInteger(at: buf.readerIndex + 4, as: UInt8.self) else { return }
                let dLen = Int(dLenU8)
                headerLen = 4 + 1 + dLen + 2
                guard buf.readableBytes >= headerLen,
                      let hostStr = buf.getString(at: buf.readerIndex + 5, length: dLen) else { return }
                targetHost = hostStr
            case 0x04: // IPv6
                headerLen = 4 + 16 + 2
                guard buf.readableBytes >= headerLen,
                      let v6Bytes = buf.getBytes(at: buf.readerIndex + 4, length: 16) else { return }
                var groups: [String] = []
                for idx in stride(from: 0, to: 16, by: 2) {
                    let word = (UInt16(v6Bytes[idx]) << 8) | UInt16(v6Bytes[idx + 1])
                    groups.append(String(format: "%x", word))
                }
                targetHost = groups.joined(separator: ":")
            default:
                sendSOCKS5Reply(context: context, rep: 0x08)
                context.close(promise: nil)
                return
            }

            guard let portU16 = buf.getInteger(at: buf.readerIndex + headerLen - 2, as: UInt16.self) else { return }
            buf.moveReaderIndex(forwardBy: headerLen)
            cumulativeBuffer = buf
            state = .connectingUpstream
            bridgeToSSHDirectTCPIP(
                context: context,
                targetHost: targetHost,
                targetPort: Int(portU16),
                isHTTPConnect: false
            )

        case .httpConnectAccumulatingHeader:
            guard buf.readableBytes <= 8192 else {
                context.close(promise: nil)
                return
            }
            guard let preview = buf.getString(at: buf.readerIndex, length: buf.readableBytes),
                  let delimiterRange = preview.range(of: "\r\n\r\n") else {
                return
            }
            let consumedBytes = preview[..<delimiterRange.upperBound].utf8.count
            let headerSection = String(preview[..<delimiterRange.lowerBound])
            buf.moveReaderIndex(forwardBy: consumedBytes)
            cumulativeBuffer = buf

            let requestLine = headerSection.components(separatedBy: "\r\n").first ?? ""
            let tokens = requestLine.split(separator: " ")
            guard tokens.count >= 2, tokens[0].uppercased() == "CONNECT" else {
                var badMethod = context.channel.allocator.buffer(capacity: 64)
                badMethod.writeString("HTTP/1.1 405 Method Not Allowed\r\n\r\n")
                context.writeAndFlush(wrapOutboundOut(badMethod)).whenComplete { _ in
                    context.close(promise: nil)
                }
                return
            }

            let authority = String(tokens[1])
            guard let colonIdx = authority.lastIndex(of: ":") else {
                context.close(promise: nil)
                return
            }
            var host = String(authority[..<colonIdx])
            if host.hasPrefix("[") && host.hasSuffix("]") {
                host = String(host.dropFirst().dropLast())
            }
            guard let portNum = Int(authority[authority.index(after: colonIdx)...]),
                  (1...65535).contains(portNum),
                  !host.isEmpty else {
                context.close(promise: nil)
                return
            }

            state = .connectingUpstream
            bridgeToSSHDirectTCPIP(
                context: context,
                targetHost: host,
                targetPort: portNum,
                isHTTPConnect: true
            )

        case .connectingUpstream:
            break
        }
    }

    private func bridgeToSSHDirectTCPIP(
        context: ChannelHandlerContext,
        targetHost: String,
        targetPort: Int,
        isHTTPConnect: Bool
    ) {
        let localChannel = context.channel
        let acc = self.accumulator
        let clientSideGlue = JaroSSHDirectTCPIPGlueHandler(
            partnerChannel: nil,
            isSSHChannelSide: false,
            accumulator: acc
        )

        sshEngine.openDirectTCPIPChannel(
            targetHost: targetHost,
            targetPort: targetPort,
            originatorAddress: localChannel.remoteAddress
        ) { sshChildChannel in
            let sshSideGlue = JaroSSHDirectTCPIPGlueHandler(
                partnerChannel: localChannel,
                isSSHChannelSide: true,
                accumulator: acc
            )
            clientSideGlue.setPartner(sshChildChannel)
            return sshChildChannel.pipeline.addHandler(sshSideGlue)
        }.whenComplete { [weak self] result in
            guard let self = self else { return }
            localChannel.eventLoop.execute {
                switch result {
                case .success(let sshChildChannel):
                    if isHTTPConnect {
                        var okBuf = localChannel.allocator.buffer(capacity: 48)
                        okBuf.writeString("HTTP/1.1 200 Connection Established\r\n\r\n")
                        localChannel.writeAndFlush(okBuf, promise: nil)
                    } else {
                        self.sendSOCKS5ReplyOnChannel(localChannel, rep: 0x00)
                    }

                    let leftover = self.cumulativeBuffer
                    self.cumulativeBuffer = nil
                    localChannel.pipeline.addHandler(clientSideGlue).flatMap {
                        localChannel.pipeline.removeHandler(self)
                    }.whenComplete { _ in
                        if let rem = leftover, rem.readableBytes > 0 {
                            acc.recordTX(rem.readableBytes)
                            let wrapped = SSHChannelData(type: .channel, data: .byteBuffer(rem))
                            sshChildChannel.writeAndFlush(wrapped, promise: nil)
                        }
                    }

                case .failure(let err):
                    self.logBuffer.append(
                        level: "WARN",
                        component: "JaroLocalSOCKS5Server",
                        message: "SSH DirectTCPIP to \(targetHost):\(targetPort) failed: \(err.localizedDescription)"
                    )
                    if isHTTPConnect {
                        var errBuf = localChannel.allocator.buffer(capacity: 48)
                        errBuf.writeString("HTTP/1.1 502 Bad Gateway\r\n\r\n")
                        localChannel.writeAndFlush(errBuf).whenComplete { _ in
                            localChannel.close(promise: nil)
                        }
                    } else {
                        self.sendSOCKS5ReplyOnChannel(localChannel, rep: 0x05)
                        localChannel.close(promise: nil)
                    }
                }
            }
        }
    }

    private func sendSOCKS5Reply(context: ChannelHandlerContext, rep: UInt8) {
        sendSOCKS5ReplyOnChannel(context.channel, rep: rep)
    }

    private func sendSOCKS5ReplyOnChannel(_ channel: Channel, rep: UInt8) {
        var reply = channel.allocator.buffer(capacity: 10)
        reply.writeBytes([0x05, rep, 0x00, 0x01, 127, 0, 0, 1])
        reply.writeInteger(UInt16(clamping: localPort))
        channel.writeAndFlush(reply, promise: nil)
    }
}

/// Loopback-only (`127.0.0.1`) local SOCKS5 + HTTP CONNECT proxy server running inside `NEPacketTunnelProvider`.
public final class JaroLocalSOCKS5Server: @unchecked Sendable {
    private let lock = NSLock()
    private let sshEngine: JaroNativeSSHEngine
    private let logBuffer: JaroRingLogBuffer
    public let trafficAccumulator = JaroProxyTrafficAccumulator()

    private var eventLoopGroup: EventLoopGroup?
    private var serverChannel: Channel?
    public private(set) var boundPort: Int = 0

    public init(sshEngine: JaroNativeSSHEngine, logBuffer: JaroRingLogBuffer) {
        self.sshEngine = sshEngine
        self.logBuffer = logBuffer
    }

    public var isListening: Bool {
        lock.lock()
        let ch = serverChannel
        lock.unlock()
        return ch?.isActive ?? false
    }

    public func start(bindHost: String = "127.0.0.1", port: Int = 1080) async throws -> Int {
        guard bindHost == "127.0.0.1" || bindHost == "::1" || bindHost == "localhost" else {
            throw JaroLocalProxyError.nonLoopbackBindForbidden(bindHost)
        }
        try await stop()

        let normalizedHost = bindHost == "localhost" ? "127.0.0.1" : bindHost
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let sshRef = self.sshEngine
        let accRef = self.trafficAccumulator
        let logRef = self.logBuffer

        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.backlog, value: 32)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { childChannel in
                let actualPort = childChannel.localAddress?.port ?? port
                let handler = JaroDualProtocolHandshakeHandler(
                    sshEngine: sshRef,
                    localPort: actualPort,
                    accumulator: accRef,
                    logBuffer: logRef
                )
                return childChannel.pipeline.addHandler(handler)
            }

        do {
            let channel = try await bootstrap.bind(host: normalizedHost, port: port).get()
            let assignedPort = channel.localAddress?.port ?? port
            lock.lock()
            self.eventLoopGroup = group
            self.serverChannel = channel
            self.boundPort = assignedPort
            lock.unlock()

            logBuffer.append(
                level: "INFO",
                component: "JaroLocalSOCKS5Server",
                message: "Dual SOCKS5 + HTTP CONNECT proxy listening on \(normalizedHost):\(assignedPort)"
            )
            return assignedPort
        } catch {
            try? await group.shutdownGracefully()
            throw error
        }
    }

    public func stop() async throws {
        lock.lock()
        let ch = serverChannel
        let grp = eventLoopGroup
        serverChannel = nil
        eventLoopGroup = nil
        boundPort = 0
        lock.unlock()

        if let ch = ch, ch.isActive {
            try? await ch.close().get()
        }
        if let grp = grp {
            try await grp.shutdownGracefully()
        }
    }
}
