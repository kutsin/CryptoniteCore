// swift-tools-version:5.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "CryptoniteCore",
    platforms: [
        .macOS(.v10_11), .iOS(.v9), .watchOS(.v2)
    ],
    products: [
        .library(
            name: "CryptoniteCore",
            targets: ["CryptoniteCore"]),
    ],
    dependencies: [
        .package(url: "https://github.com/kutsin/DevKit.git", .upToNextMajor(from: "1.0.0")),
        .package(url: "https://github.com/weichsel/ZIPFoundation.git", .upToNextMajor(from: "0.9.0"))
    ],
    targets: [
        .target(
            name: "CryptoniteCore",
            dependencies: [.product(name: "DevKit", package: "DevKit"),
                           .product(name: "ZIPFoundation", package: "ZIPFoundation")])
    ]
)
