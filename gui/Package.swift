// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "SSTPClient",
    platforms: [.macOS(.v14)],
    targets: [
        .executableTarget(
            name: "SSTPClient",
            swiftSettings: [.swiftLanguageMode(.v5)]
        )
    ]
)
