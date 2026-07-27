import Foundation

struct CertificateInfo: Decodable, Identifiable, Hashable {
    let ckaid: String
    let label: String?
    let subject: String
    let issuer: String
    let upn: String?
    let expires: String
    let expired: Bool
    let selfSigned: Bool
    let canAuthenticate: Bool
    let suitable: Bool

    var id: String { ckaid }

    var commonName: String {
        for part in subject.split(separator: ",") {
            let trimmed = part.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("CN=") {
                return String(trimmed.dropFirst(3))
            }
        }
        return subject
    }

    var expiryDate: Date? {
        ISO8601DateFormatter().date(from: expires)
            ?? ISO8601DateFormatter.withFractionalSeconds.date(from: expires)
    }

    var expiryText: String {
        guard let date = expiryDate else { return expires }
        return DateFormatter.shortDay.string(from: date)
    }

    /// Re-issuing a smart card certificate takes days of paperwork, so the
    /// warning has to appear well before the tunnel starts failing.
    var expiresSoon: Bool {
        guard let date = expiryDate else { return false }
        return date.timeIntervalSinceNow < 30 * 24 * 3600
    }
}

struct Profile: Codable, Identifiable, Hashable {
    var id = UUID()
    var name: String
    var server = ""
    var username = ""
    var defaultRoute = true
    var setDNS = true
    var routes = ""
    var dnsDomains = ""
    /// The certificate is remembered by CKA_ID, and its name is kept alongside
    /// so the profile still reads sensibly with the token unplugged.
    var ckaid: String?
    var certificateName: String?
}

struct TokenDescription: Decodable, Identifiable, Hashable {
    let module: String
    let slot: Int
    let label: String
    let serial: String
    let pinLocked: Bool
    let pinFinalTry: Bool
    let pinCountLow: Bool
    let certificates: [CertificateInfo]

    // Slot numbers are only unique within one middleware, and two of them can
    // report cards at the same time.
    var id: String { "\(module)#\(slot)" }

    /// The card also carries e-mail and signing certificates; the server would
    /// reject those, so only the usable ones are offered.
    var usableCertificates: [CertificateInfo] {
        certificates.filter { $0.suitable }
    }

    var pinWarning: String? {
        if pinLocked { return "PIN заблокирован" }
        if pinFinalTry { return "осталась последняя попытка PIN" }
        if pinCountLow { return "были неудачные попытки ввода PIN" }
        return nil
    }
}

struct TunnelStatus: Decodable {
    var state: String
    var since: Double?
    var server: String?
    var error: String?
    var interface: String?
    var address: String?
    var peer: String?
    var dns: [String]?
    var rxBytes: Int?
    var txBytes: Int?

    static let idle = TunnelStatus(state: "idle")

    var isBusy: Bool { state == "connecting" }
    var isConnected: Bool { state == "connected" }

    var title: String {
        switch state {
        case "idle": return "Не подключено"
        case "connecting": return "Подключение…"
        case "connected": return "Подключено"
        case "disconnected": return "Отключено"
        case "failed": return "Ошибка"
        default: return state
        }
    }
}

extension DateFormatter {
    static let shortDay: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "dd.MM.yyyy"
        return formatter
    }()
}

extension ISO8601DateFormatter {
    static let withFractionalSeconds: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter
    }()
}
