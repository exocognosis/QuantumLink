// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "QuantumLink",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .executable(name: "QuantumLinkApp", targets: ["QuantumLinkApp"]),
        .executable(name: "QuantumLinkSmoke", targets: ["QuantumLinkSmoke"]),
        .library(name: "QuantumLinkKit", targets: ["QuantumLinkKit"]),
        .library(name: "QuantumLinkTunnel", targets: ["QuantumLinkTunnel"])
    ],
    targets: [
        .target(name: "QuantumLinkKit"),
        .executableTarget(
            name: "QuantumLinkApp",
            dependencies: ["QuantumLinkKit"],
            resources: [
                .process("Resources")
            ]
        ),
        .executableTarget(
            name: "QuantumLinkSmoke",
            dependencies: ["QuantumLinkKit"]
        ),
        .target(
            name: "QuantumLinkTunnel",
            dependencies: ["QuantumLinkKit"]
        ),
        .testTarget(
            name: "QuantumLinkKitTests",
            dependencies: ["QuantumLinkKit"]
        )
    ]
)
