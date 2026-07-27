import Foundation
import SwiftUI

@MainActor
final class TunnelModel: ObservableObject {
    @Published var status = TunnelStatus.idle
    @Published var daemonReachable = false
    @Published var tokens: [TokenDescription] = []
    @Published var message: String?
    @Published var busy = false

    @Published var profiles: [Profile] = [] { didSet { persist() } }
    @Published var currentProfileID: Profile.ID? { didSet { persist() } }

    private var events: DaemonConnection?
    private let queue = DispatchQueue(label: "sstp.daemon", qos: .userInitiated)

    var certificates: [CertificateInfo] {
        tokens.flatMap(\.usableCertificates)
    }

    var tokenWarning: String? {
        tokens.compactMap(\.pinWarning).first
    }

    var canConnect: Bool {
        !busy && daemonReachable && selectedCertificate != nil
            && !profile.server.trimmingCharacters(in: .whitespaces).isEmpty
    }

    // ---------------------------------------------------------------- profiles

    var profile: Profile {
        get { profiles.first { $0.id == currentProfileID } ?? profiles[0] }
        set {
            guard let index = profiles.firstIndex(where: { $0.id == newValue.id })
            else { return }
            profiles[index] = newValue
        }
    }

    var selectedCertificate: CertificateInfo? {
        get { certificates.first { $0.ckaid == profile.ckaid } }
        set {
            profile.ckaid = newValue?.ckaid
            profile.certificateName = newValue?.commonName
        }
    }

    /// The certificate a profile is bound to that the inserted token does not
    /// carry, if any.
    var missingCertificate: String? {
        guard profile.ckaid != nil, selectedCertificate == nil else { return nil }
        return profile.certificateName ?? "выбранный ранее"
    }

    func addProfile() {
        let created = Profile(name: "Новый профиль")
        profiles.append(created)
        currentProfileID = created.id
    }

    func removeCurrentProfile() {
        guard profiles.count > 1 else { return }
        profiles.removeAll { $0.id == currentProfileID }
        currentProfileID = profiles.first?.id
    }

    private static let profilesKey = "profiles"
    private static let currentKey = "currentProfile"

    private func load() {
        let defaults = UserDefaults.standard
        if let data = defaults.data(forKey: Self.profilesKey),
           let stored = try? JSONDecoder().decode([Profile].self, from: data),
           !stored.isEmpty {
            profiles = stored
        } else {
            profiles = [Self.migrated()]
        }
        let saved = defaults.string(forKey: Self.currentKey).flatMap(UUID.init(uuidString:))
        currentProfileID = profiles.contains { $0.id == saved } ? saved : profiles[0].id
    }

    /// The single set of settings the app kept before profiles existed. Getting
    /// a working tunnel configured took a while; an upgrade must not discard it.
    private static func migrated() -> Profile {
        let defaults = UserDefaults.standard
        let server = defaults.string(forKey: "server") ?? ""
        return Profile(
            name: server.isEmpty ? "Новый профиль" : server,
            server: server,
            username: defaults.string(forKey: "username") ?? "",
            defaultRoute: defaults.object(forKey: "defaultRoute") as? Bool ?? true,
            setDNS: defaults.object(forKey: "setDNS") as? Bool ?? true,
            routes: defaults.string(forKey: "routes") ?? "",
            dnsDomains: defaults.string(forKey: "dnsDomains") ?? ""
        )
    }

    private func persist() {
        let defaults = UserDefaults.standard
        if let data = try? JSONEncoder().encode(profiles) {
            defaults.set(data, forKey: Self.profilesKey)
        }
        defaults.set(currentProfileID?.uuidString, forKey: Self.currentKey)
    }

    // ------------------------------------------------------------------ events

    init() {
        load()
        // The menu bar item shows the tunnel state before the window is ever
        // opened, so the event stream cannot wait for a view to appear.
        listen()
    }

    /// Keep one connection open purely for state broadcasts, so replies to
    /// commands never have to be told apart from events.
    ///
    /// This blocks forever, so it gets a thread of its own: on the command
    /// queue it would starve every request behind it.
    private func listen() {
        let thread = Thread { [weak self] in
            while true {
                do {
                    let (connection, initial) = try DaemonClient.subscribe()
                    Task { @MainActor [weak self] in
                        self?.events = connection
                        self?.daemonReachable = true
                        self?.status = initial
                    }
                    while true {
                        let line = try connection.read()
                        guard let envelope = try? DaemonClient.decoder.decode(
                            EventEnvelope.self, from: line), envelope.event == "state"
                        else { continue }
                        let update = try DaemonClient.decoder.decode(TunnelStatus.self, from: line)
                        Task { @MainActor [weak self] in self?.apply(update) }
                    }
                } catch {
                    Task { @MainActor [weak self] in
                        self?.daemonReachable = false
                        self?.events = nil
                    }
                    // The daemon may simply not be up yet; keep trying quietly.
                    Thread.sleep(forTimeInterval: 3)
                }
            }
        }
        thread.name = "sstp.events"
        thread.start()
    }

    private func apply(_ update: TunnelStatus) {
        status = update
        busy = update.isBusy
        if update.state == "failed" {
            message = update.error
        } else if update.isConnected {
            message = nil
        }
    }

    func refreshStatus() {
        perform { try DaemonClient.status() } completion: { [weak self] status in
            self?.status = status
            self?.busy = status.isBusy
        }
    }

    // ------------------------------------------------------------------ tokens

    func refreshTokens() {
        perform { try DaemonClient.tokens() } completion: { [weak self] tokens in
            guard let self else { return }
            self.tokens = tokens
            // A profile that has never been used adopts whatever is on the
            // card, but one whose certificate is absent keeps its binding:
            // silently authenticating as a different identity would be worse
            // than refusing to connect.
            if self.profile.ckaid == nil {
                self.selectedCertificate = self.certificates.first
            }
        }
    }

    // ----------------------------------------------------------------- actions

    func connect(pin: String) {
        guard let certificate = selectedCertificate,
              let token = tokens.first(where: { token in
                  token.certificates.contains(where: { $0.ckaid == certificate.ckaid })
              })
        else { return }

        let profile = self.profile
        var request: [String: Any] = [
            "server": profile.server.trimmingCharacters(in: .whitespaces),
            "pin": pin,
            "module": token.module,
            "slot": token.slot,
            "ckaid": certificate.ckaid,
            "default_route": profile.defaultRoute,
            "set_dns": profile.setDNS,
        ]
        let identity = profile.username.trimmingCharacters(in: .whitespaces)
        if !identity.isEmpty { request["username"] = identity }
        let extraRoutes = Self.split(profile.routes)
        if !extraRoutes.isEmpty { request["routes"] = extraRoutes }
        let domains = Self.split(profile.dnsDomains)
        if !domains.isEmpty { request["dns_domains"] = domains }

        busy = true
        message = nil
        perform { try DaemonClient.call("connect", request) } completion: { _ in }
    }

    func installService() {
        busy = true
        message = nil
        perform { try ServiceInstaller.install() } completion: { [weak self] in
            // The event thread reconnects on its own once the socket appears.
            self?.busy = false
        }
    }

    func disconnect() {
        busy = true
        perform { try DaemonClient.call("disconnect") } completion: { [weak self] _ in
            self?.busy = false
        }
    }

    private static func split(_ value: String) -> [String] {
        value.split(whereSeparator: { ", \n\t".contains($0) }).map(String.init)
    }

    // ------------------------------------------------------------------ plumbing

    private func perform<T>(_ work: @escaping () throws -> T,
                            completion: @escaping (T) -> Void) {
        queue.async { [weak self] in
            do {
                let value = try work()
                Task { @MainActor in completion(value) }
            } catch {
                Task { @MainActor [weak self] in
                    self?.busy = false
                    self?.message = error.localizedDescription
                    if case DaemonClientError.notRunning = error {
                        self?.daemonReachable = false
                    }
                }
            }
        }
    }
}
