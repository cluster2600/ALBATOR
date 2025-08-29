// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "Albator-Swift",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(
            name: "Albator-Swift",
            targets: ["Albator-Swift"]
        )
    ],
    dependencies: [],
    targets: [
        .executableTarget(
            name: "Albator-Swift",
            dependencies: [],
            path: "Sources/Albator",
            sources: ["main.swift"]
        ),
        .target(
            name: "AlbatorCore",
            dependencies: [],
            path: "Sources/Albator",
            exclude: ["main.swift"]
        ),
        .testTarget(
            name: "AlbatorTests",
            dependencies: ["AlbatorCore"],
            path: "Tests/AlbatorTests"
        )
    ]
)
