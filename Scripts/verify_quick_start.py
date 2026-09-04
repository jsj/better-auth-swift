#!/usr/bin/env python3
"""Compile the actual README SwiftUI example as a separate SDK consumer."""
import json
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parent.parent
readme = (root / "README.md").read_text()
section = readme.split("<!-- swiftui-quick-start -->", 1)[1]
swift = section.split("```swift\n", 1)[1].split("```", 1)[0]
package = root / ".build" / "quick-start-consumer"
source = package / "Sources" / "QuickStart"
source.mkdir(parents=True, exist_ok=True)
(source / "main.swift").write_text(swift)
(package / "Package.swift").write_text('''// swift-tools-version: 6.0
import PackageDescription
let package = Package(
    name: "QuickStartConsumer",
    platforms: [.macOS(.v14)],
    dependencies: [.package(path: ROOT)],
    targets: [.executableTarget(name: "QuickStart", dependencies: [
        .product(name: "BetterAuth", package: "better-auth-swift"),
        .product(name: "BetterAuthEmailPassword", package: "better-auth-swift"),
        .product(name: "BetterAuthSwiftUI", package: "better-auth-swift")
    ])],
    swiftLanguageModes: [.v6]
)
'''.replace("ROOT", json.dumps(str(root))))
subprocess.run(["swift", "build", "--package-path", str(package)], check=True)
