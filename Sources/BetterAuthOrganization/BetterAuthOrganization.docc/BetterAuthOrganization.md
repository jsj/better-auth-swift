# ``BetterAuthOrganization``

Use the Better Auth organization plugin from a Swift application.

## Overview

BetterAuthOrganization keeps organization features separate from the main library. Add this product only when the server uses the organization plugin.

The module supports organizations, members, roles, and invitations.

### Enable the module

Add the organization module when you create the client.

```swift
import BetterAuth
import BetterAuthOrganization

let client = BetterAuthClient(
    configuration: BetterAuthConfiguration(
        baseURL: URL(string: "https://auth.example.com")!
    ),
    modules: [BetterAuthOrganizationModule()]
)
```

## Topics

### Organization access

- ``BetterAuthOrganizationModule``
- ``OrganizationManager``
