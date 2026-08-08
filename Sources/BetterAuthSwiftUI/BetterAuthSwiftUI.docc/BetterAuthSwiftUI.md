# ``BetterAuthSwiftUI``

Connect Better Auth session state to a SwiftUI application.

## Overview

BetterAuthSwiftUI provides an observable store for authentication state. The store reports launch, session, and request state.

### Create the store

Create one store for the application. Then restore the stored session.

```swift
import BetterAuth
import BetterAuthSwiftUI
import SwiftUI

@main
struct ExampleApp: App {
    @State private var authStore = AuthStore(client: client)

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environment(authStore)
                .task {
                    await authStore.restore()
                }
        }
    }
}
```

## Topics

### Session state

- ``AuthStore``
- ``AuthLaunchState``
