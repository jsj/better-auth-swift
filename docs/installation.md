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
    .package(url: "https://github.com/jsj/better-auth-swift.git", from: "0.0.1")
]
```

Then choose the product you need:

```swift
.target(
    name: "YourApp",
    dependencies: [
        .product(name: "BetterAuth", package: "better-auth-swift"),
        .product(name: "BetterAuthSwiftUI", package: "better-auth-swift")
    ]
)
```

Use only `BetterAuth` if you want the core SDK. Add `BetterAuthSwiftUI` when you want the optional `AuthStore` wrapper for SwiftUI state.

## Xcode

In Xcode, add the repository URL in the Swift Package Dependencies UI and select the products your target needs.

## First client

```swift
import BetterAuth

let client = BetterAuthClient(
    baseURL: URL(string: "https://your-api.example.com")!
)
```

Once you have a client, the usual first step is restoring any previously stored session:

```swift
let session = try await client.auth.restoreOrRefreshSession()
```

If you need to load the stored session separately before restoring app state, read it through the session manager actor:

```swift
let stored = try await client.auth.loadStoredSession()
```
