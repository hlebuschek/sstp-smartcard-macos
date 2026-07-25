import Foundation

enum ServiceInstallerError: LocalizedError {
    case missingPayload
    case failed(String)

    var errorDescription: String? {
        switch self {
        case .missingPayload:
            return "В приложении нет встроенного ядра — пересоберите его через make-app.sh"
        case .failed(let detail):
            return "Не удалось установить службу: \(detail)"
        }
    }
}

/// Registers the bundled Python core as a launchd system daemon.
///
/// The daemon needs root — it opens utun and rewrites routes and DNS — so the
/// installation goes through the standard authorisation prompt.
enum ServiceInstaller {
    static func install() throws {
        guard let script = Bundle.main.resourceURL?
            .appendingPathComponent("sstp.sh").path,
            FileManager.default.isExecutableFile(atPath: script)
        else { throw ServiceInstallerError.missingPayload }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        // The path is handed over as an argument and quoted by AppleScript
        // itself: the bundle normally lives under a name with a space in it.
        process.arguments = [
            "-e", "on run argv",
            "-e", "do shell script (quoted form of item 1 of argv) & \" install\""
                + " with administrator privileges",
            "-e", "end run",
            script,
        ]
        let errors = Pipe()
        process.standardOutput = Pipe()
        process.standardError = errors
        try process.run()
        let detail = String(
            data: errors.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8
        ) ?? ""
        process.waitUntilExit()

        // -128 is the user dismissing the password prompt, which needs no report.
        guard process.terminationStatus != 0, !detail.contains("-128") else { return }
        throw ServiceInstallerError.failed(
            detail.trimmingCharacters(in: .whitespacesAndNewlines)
        )
    }
}
