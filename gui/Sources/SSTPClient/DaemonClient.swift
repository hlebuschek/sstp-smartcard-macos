import Foundation

let defaultSocketPath =
    ProcessInfo.processInfo.environment["SSTP_SOCKET"] ?? "/var/run/sstp.sock"

enum DaemonClientError: LocalizedError {
    case notRunning
    case notPermitted
    case socket(String)
    case closed
    case malformed(String)
    case refused(String)

    var errorDescription: String? {
        switch self {
        case .notRunning:
            return "Демон не запущен: sudo sstp daemon"
        case .notPermitted:
            return "Нет доступа к \(defaultSocketPath); нужна группа admin"
        case .socket(let detail):
            return detail
        case .closed:
            return "Демон закрыл соединение"
        case .malformed(let detail):
            return "Некорректный ответ демона: \(detail)"
        case .refused(let detail):
            return detail
        }
    }
}

/// One connection to the daemon, framing newline-delimited JSON.
///
/// Blocking by design: every call is made from a background queue, never from
/// the main actor.
final class DaemonConnection {
    private var descriptor: Int32
    private var buffer = Data()

    init(path: String = defaultSocketPath, timeout: TimeInterval = 30) throws {
        descriptor = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else {
            throw DaemonClientError.socket("socket(): \(String(cString: strerror(errno)))")
        }

        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        guard bytes.count < MemoryLayout.size(ofValue: address.sun_path) else {
            Darwin.close(descriptor)
            throw DaemonClientError.socket("путь к сокету слишком длинный")
        }
        withUnsafeMutableBytes(of: &address.sun_path) { destination in
            destination.copyBytes(from: bytes)
        }

        let length = socklen_t(MemoryLayout<sockaddr_un>.size)
        let result = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { generic in
                Darwin.connect(descriptor, generic, length)
            }
        }
        if result != 0 {
            let code = errno
            Darwin.close(descriptor)
            switch code {
            case ENOENT, ECONNREFUSED: throw DaemonClientError.notRunning
            case EACCES, EPERM: throw DaemonClientError.notPermitted
            default: throw DaemonClientError.socket(String(cString: strerror(code)))
            }
        }

        if timeout > 0 {
            var value = timeval(
                tv_sec: Int(timeout),
                tv_usec: Int32((timeout - Double(Int(timeout))) * 1_000_000)
            )
            setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &value,
                       socklen_t(MemoryLayout<timeval>.size))
        }
    }

    deinit {
        shutdownConnection()
    }

    func shutdownConnection() {
        if descriptor >= 0 {
            Darwin.close(descriptor)
            descriptor = -1
        }
    }

    func write(_ message: [String: Any]) throws {
        var payload = try JSONSerialization.data(withJSONObject: message)
        payload.append(0x0A)
        try payload.withUnsafeBytes { raw in
            var offset = 0
            while offset < raw.count {
                let written = Darwin.send(descriptor, raw.baseAddress!.advanced(by: offset),
                                          raw.count - offset, 0)
                if written <= 0 {
                    throw DaemonClientError.socket(String(cString: strerror(errno)))
                }
                offset += written
            }
        }
    }

    func read() throws -> Data {
        while true {
            if let newline = buffer.firstIndex(of: 0x0A) {
                let line = buffer[buffer.startIndex..<newline]
                buffer.removeSubrange(buffer.startIndex...newline)
                if !line.isEmpty {
                    return Data(line)
                }
                continue
            }
            var chunk = [UInt8](repeating: 0, count: 65536)
            let count = Darwin.recv(descriptor, &chunk, chunk.count, 0)
            if count == 0 {
                throw DaemonClientError.closed
            }
            if count < 0 {
                throw DaemonClientError.socket(String(cString: strerror(errno)))
            }
            buffer.append(contentsOf: chunk[0..<count])
        }
    }
}

private struct ErrorReply: Decodable {
    let ok: Bool
    let error: String?
}

private struct StatusReply: Decodable {
    let status: TunnelStatus
}

private struct TokensReply: Decodable {
    let tokens: [TokenDescription]
}

struct EventEnvelope: Decodable {
    let event: String?
}

enum DaemonClient {
    static let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return decoder
    }()

    private static func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        let outcome = try decoder.decode(ErrorReply.self, from: data)
        guard outcome.ok else {
            throw DaemonClientError.refused(outcome.error ?? "команда отклонена")
        }
        do {
            return try decoder.decode(type, from: data)
        } catch {
            throw DaemonClientError.malformed(String(describing: error))
        }
    }

    /// Send one command on a fresh connection and return the reply.
    static func call<T: Decodable>(_ command: String,
                                   _ arguments: [String: Any] = [:],
                                   expecting type: T.Type,
                                   path: String = defaultSocketPath) throws -> T {
        let connection = try DaemonConnection(path: path)
        defer { connection.shutdownConnection() }
        var message = arguments
        message["command"] = command
        try connection.write(message)
        return try decode(type, from: try connection.read())
    }

    static func call(_ command: String,
                     _ arguments: [String: Any] = [:],
                     path: String = defaultSocketPath) throws {
        _ = try call(command, arguments, expecting: ErrorReply.self, path: path)
    }

    static func status(path: String = defaultSocketPath) throws -> TunnelStatus {
        try call("status", expecting: StatusReply.self, path: path).status
    }

    static func tokens(module: String? = nil,
                       path: String = defaultSocketPath) throws -> [TokenDescription] {
        var arguments: [String: Any] = [:]
        if let module { arguments["module"] = module }
        return try call("tokens", arguments, expecting: TokensReply.self, path: path).tokens
    }

    /// Open a long-lived connection that receives state broadcasts.
    static func subscribe(path: String = defaultSocketPath) throws -> (DaemonConnection, TunnelStatus) {
        let connection = try DaemonConnection(path: path, timeout: 0)
        try connection.write(["command": "subscribe"])
        let reply = try decode(StatusReply.self, from: try connection.read())
        return (connection, reply.status)
    }
}
