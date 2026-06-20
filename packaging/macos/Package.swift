// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "NmapUI",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(
            name: "NmapUI",
            targets: ["NmapUIApp"]
        ),
        .executable(
            name: "GoogleDriveHelper",
            targets: ["GoogleDriveHelper"]
        )
    ],
    targets: [
        .executableTarget(
            name: "NmapUIApp",
            path: "Sources/NmapUIApp",
            exclude: [
                "Resources/Info.plist"
            ],
            resources: [
                .process("Assets")
            ]
        ),
        .executableTarget(
            name: "GoogleDriveHelper",
            path: "Sources/GoogleDriveHelper"
        )
    ]
)
