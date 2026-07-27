import SwiftUI

struct MenuView: View {
    @ObservedObject var model: TunnelModel
    @State private var pin = ""
    @FocusState private var pinFocused: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            header
            Divider()

            if model.serviceOutdated {
                serviceOutdated
                Divider()
            }

            if !model.daemonReachable {
                daemonMissing
            } else if model.status.isConnected {
                connected
            } else {
                form
            }

            if let message = model.message {
                Text(message)
                    .font(.callout)
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Divider()
            HStack {
                Button("Обновить") { model.refreshTokens(); model.refreshStatus() }
                Spacer()
                Button("Выйти") { NSApplication.shared.terminate(nil) }
            }
            .buttonStyle(.link)
            .font(.callout)
        }
        .padding(16)
        .frame(width: 340)
        .onAppear { model.refreshTokens() }
    }

    private var header: some View {
        HStack(spacing: 8) {
            Circle()
                .fill(indicatorColor)
                .frame(width: 9, height: 9)
            VStack(alignment: .leading, spacing: 2) {
                Text(model.status.title).font(.headline)
                if let server = model.status.server, model.status.isConnected {
                    Text(server).font(.caption).foregroundStyle(.secondary)
                }
            }
            Spacer()
            if model.busy {
                ProgressView().controlSize(.small)
            }
        }
    }

    private var indicatorColor: Color {
        if model.status.isConnected { return .green }
        if model.busy { return .orange }
        if model.status.state == "failed" { return .red }
        return .secondary
    }

    private var daemonMissing: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Служба не установлена").font(.callout)
            Text("Туннель поднимается от имени root, поэтому фоновая служба "
                 + "ставится один раз и запрашивает пароль администратора.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Button("Установить службу") { model.installService() }
                .keyboardShortcut(.defaultAction)
                .disabled(model.busy)
        }
    }

    private var serviceOutdated: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Служба устарела", systemImage: "exclamationmark.triangle")
                .font(.callout)
                .foregroundStyle(.orange)
            Text("Фоновая служба работает на коде предыдущей версии приложения: "
                 + "она ставится отдельной копией и сама не обновляется. Пока её "
                 + "не переустановить, часть токенов может не определяться.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Button("Обновить службу") { model.installService() }
                .disabled(model.busy)
        }
    }

    private var connected: some View {
        VStack(alignment: .leading, spacing: 6) {
            row("Интерфейс", model.status.interface)
            row("Адрес", model.status.address)
            row("DNS", model.status.dns?.joined(separator: ", "))
            if let rx = model.status.rxBytes, let tx = model.status.txBytes {
                row("Трафик", "↓ \(format(rx))  ↑ \(format(tx))")
            }
            Button("Отключиться") { model.disconnect() }
                .keyboardShortcut(.defaultAction)
                .disabled(model.busy)
                .padding(.top, 4)
        }
    }

    private var form: some View {
        VStack(alignment: .leading, spacing: 10) {
            LabeledContent("Профиль") {
                HStack(spacing: 4) {
                    Picker("", selection: $model.currentProfileID) {
                        ForEach(model.profiles) { profile in
                            Text(profile.name).tag(Optional(profile.id))
                        }
                    }
                    .labelsHidden()
                    Button { model.addProfile() } label: { Image(systemName: "plus") }
                        .help("Новый профиль")
                    Button { model.removeCurrentProfile() } label: {
                        Image(systemName: "minus")
                    }
                    .help("Удалить профиль")
                    .disabled(model.profiles.count < 2)
                }
                .buttonStyle(.borderless)
            }

            LabeledContent("Название") {
                TextField("", text: $model.profile.name)
                    .textFieldStyle(.roundedBorder)
            }

            LabeledContent("Сервер") {
                TextField("vpn.example.com", text: $model.profile.server)
                    .textFieldStyle(.roundedBorder)
            }

            if model.certificates.isEmpty {
                Text("Нет сертификатов для аутентификации — вставьте токен и нажмите «Обновить».")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                LabeledContent("Сертификат") {
                    Picker("", selection: $model.selectedCertificate) {
                        ForEach(model.certificates) { certificate in
                            Text("\(certificate.commonName) — до \(certificate.expiryText)")
                                .tag(Optional(certificate))
                        }
                    }
                    .labelsHidden()
                }
                if let certificate = model.selectedCertificate {
                    HStack(alignment: .firstTextBaseline) {
                        Text(certificate.upn ?? certificate.subject)
                            .foregroundStyle(.secondary)
                        if certificate.expiresSoon {
                            Spacer()
                            Text("истекает \(certificate.expiryText)")
                                .foregroundStyle(.orange)
                        }
                    }
                    .font(.caption)
                }
            }

            if let name = model.missingCertificate {
                Label("Сертификат профиля («\(name)») на токене не найден — "
                      + "вставьте нужную карту или выберите другой сертификат.",
                      systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }

            if let warning = model.tokenWarning {
                Label(warning, systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }

            LabeledContent("PIN") {
                SecureField("", text: $pin)
                    .textFieldStyle(.roundedBorder)
                    .focused($pinFocused)
                    .onSubmit(submit)
            }

            DisclosureGroup("Дополнительно") {
                VStack(alignment: .leading, spacing: 6) {
                    LabeledContent("Имя") {
                        TextField("из UPN сертификата", text: $model.profile.username)
                            .textFieldStyle(.roundedBorder)
                    }
                    Toggle("Весь трафик через VPN", isOn: $model.profile.defaultRoute)
                    Toggle("Использовать DNS сервера VPN", isOn: $model.profile.setDNS)
                    if !model.profile.defaultRoute {
                        LabeledContent("Сети") {
                            TextField("172.16.0.0/12", text: $model.profile.routes)
                                .textFieldStyle(.roundedBorder)
                        }
                        LabeledContent("Домены") {
                            TextField("домен из UPN сертификата", text: $model.profile.dnsDomains)
                                .textFieldStyle(.roundedBorder)
                        }
                        if model.profile.routes.trimmingCharacters(in: .whitespaces).isEmpty {
                            Label("Список сетей пуст — в туннель не пойдёт ничего.",
                                  systemImage: "exclamationmark.triangle")
                                .font(.caption)
                                .foregroundStyle(.orange)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        Text("Через туннель идут только эти сети. На корпоративный "
                             + "DNS уходят имена перечисленных доменов, остальной "
                             + "интернет резолвится как раньше. Если поле пустое, "
                             + "берётся домен из UPN сертификата.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .padding(.top, 6)
            }
            .font(.callout)

            Button("Подключиться", action: submit)
                .keyboardShortcut(.defaultAction)
                .disabled(!model.canConnect || pin.isEmpty)
        }
    }

    private func submit() {
        guard model.canConnect, !pin.isEmpty else { return }
        model.connect(pin: pin)
        // The PIN is needed once, for C_Login; it is never kept around.
        pin = ""
    }

    private func row(_ title: String, _ value: String?) -> some View {
        HStack(alignment: .top) {
            Text(title).foregroundStyle(.secondary)
            Spacer()
            Text(value ?? "—").multilineTextAlignment(.trailing)
        }
        .font(.callout)
    }

    private func format(_ bytes: Int) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .binary)
    }
}
