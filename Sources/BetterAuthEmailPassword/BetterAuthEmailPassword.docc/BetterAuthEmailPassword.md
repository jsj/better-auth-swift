# ``BetterAuthEmailPassword``

Use email and password authentication with a registered ``BetterAuthEmailPasswordModule``.

```swift
let client = BetterAuthClient(baseURL: authURL, modules: [BetterAuthEmailPasswordModule()])
let email = try client.requireEmailPassword()
let session = try await email.signIn(.init(email: emailAddress, password: password))
```
