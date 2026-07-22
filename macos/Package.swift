// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "QuantumLink",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .executable(name: "QuantumLink", targets: ["QuantumLinkApp"]),
        .library(name: "QuantumLinkKit", targets: ["QuantumLinkKit"]),
        .executable(name: "QuantumLinkSmoke", targets: ["QuantumLinkSmoke"]),
        .executable(name: "QuantumLinkMDM", targets: ["QuantumLinkMDM"])
    ],
    targets: [
        .target(
            name: "QuantumLinkKit",
            dependencies: []
        ),
        .executableTarget(
            name: "QuantumLinkApp",
            dependencies: ["QuantumLinkKit"],
            resources: [
                .process("Assets.xcassets"),
                .process("Resources")
            ]
        ),
        .target(
            name: "QuantumLinkTunnel",
            dependencies: ["QuantumLinkKit"]
        ),
        .executableTarget(
            name: "QuantumLinkSmoke",
            dependencies: ["QuantumLinkKit"]
        ),
        .executableTarget(
            name: "QuantumLinkMDM",
            dependencies: ["QuantumLinkKit"]
        ),
        .testTarget(
            name: "QuantumLinkKitTests",
            dependencies: ["QuantumLinkKit"]
        )
    ]
)
