// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "PEMCore",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "PEMCore", targets: ["PEMCore"]),
    ],
    targets: [
        .target(name: "PEMCore"),
        .testTarget(name: "PEMCoreTests", dependencies: ["PEMCore"]),
    ]
)
