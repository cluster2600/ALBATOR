// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "Albator-Swift",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(
            name: "Albator-Swift",
            targets: ["AlbatorSwiftCLI"]
        ),
        .executable(
            name: "Albator-SwiftGUI",
            targets: ["AlbatorSwiftGUI"]
        )
    ],
    dependencies: [],
    targets: [
        .target(
            name: "AlbatorCore",
            dependencies: [],
            path: "Sources/Albator",
            exclude: ["Albator-Swift.entitlements"]
        ),
        .executableTarget(
            name: "AlbatorSwiftCLI",
            dependencies: ["AlbatorCore"],
            path: "Sources/AlbatorCLI",
            sources: ["main.swift"]
        ),
        .executableTarget(
            name: "AlbatorSwiftGUI",
            dependencies: ["AlbatorCore"],
            path: "Sources/AlbatorGUI",
            sources: ["AlbatorApp.swift"]
        ),
        .testTarget(
            name: "AlbatorTests",
            dependencies: ["AlbatorCore"],
            path: "Tests/AlbatorTests"
        )
    ]
)
