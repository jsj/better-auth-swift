# Installation

## Requirements

- iOS 17+
- macOS 14+
- Xcode 16+
- Swift 6

## Swift Package Manager

Add the package to your app target:

```swift
dependencies: [
    .package(url: "https://github.com/jsj/better-auth-swift.git")
]
```

Then choose the products you need:

```swift
.target(
    name: "YourApp",
    dependencies: [
        .product(name: "BetterAuth", package: "better-auth-swift"),
        .product(name: "BetterAuthSwiftUI", package: "better-auth-swift"),
        .product(name: "BetterAuthOrganization", package: "better-auth-swift")
    ]
)
```

Use `BetterAuth` for the core SDK, add `BetterAuthSwiftUI` for the observable `AuthStore`, and add `BetterAuthOrganization` when using the organization plugin module.

## Xcode

In Xcode, add the repository URL in the Swift Package Dependencies UI and select the products your target needs.

## First client

```swift
import BetterAuth

let client = BetterAuthClient(
    baseURL: URL(string: "https://your-api.example.com")!
)
```

Restore app-launch state with the typed restore result:

```swift
let result = try await client.auth.restoreSessionOnLaunch()
```

For the older session-only path, use:

```swift
let session = try await client.auth.restoreOrRefreshSession()
```
