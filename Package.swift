// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SwiftKES",
    platforms: [
        .iOS(.v14),
        .macOS(.v14),
        .watchOS(.v7),
        .tvOS(.v14),
    ],
    products: [
        .library(
            name: "SwiftKES",
            targets: ["SwiftKES"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/Kingpin-Apps/swift-nacl.git", .upToNextMajor(from: "1.0.0")),
        .package(url: "https://github.com/attaswift/BigInt.git", .upToNextMinor(from: "5.3.0")),
    ],
    targets: [
        .target(
            name: "SwiftKES",
            dependencies: [
                .product(name: "SwiftNaCl", package: "swift-nacl"),
                .product(name: "BigInt", package: "BigInt"),
            ]
        ),
        .testTarget(
            name: "SwiftKESTests",
            dependencies: ["SwiftKES"],
            resources: [.copy("Resources")]
        ),
    ]
)
