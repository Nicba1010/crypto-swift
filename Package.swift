// swift-tools-version: 5.6
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
        name: "crypto-swift",
        products: [
            // Products define the executables and libraries a package produces, and make them visible to other packages.
            .library(
                    name: "crypto-swift",
                    targets: ["crypto-swift"]),
        ],
        dependencies: [
            // Dependencies declare other packages that this package depends on.
            // .package(url: /* package url */, from: "1.0.0"),
            .package(url: "https://github.com/attaswift/BigInt.git", from: "5.3.0"),
            .package(url: "https://github.com/apple/swift-crypto.git", from: "2.1.0")
        ],
        targets: [
            // Targets are the basic building blocks of a package. A target can define a module or a test suite.
            // Targets can depend on other targets in this package, and on products in packages this package depends on.
            .target(
                    name: "crypto-swift",
                    dependencies: ["BigInt", .product(name: "Crypto", package: "swift-crypto")]),
            .testTarget(
                    name: "crypto-swiftTests",
                    dependencies: ["crypto-swift"]),
        ]
)
