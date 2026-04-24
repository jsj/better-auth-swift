# Release and Support Policy

## Versioning

`better-auth-swift` uses semantic versioning for tagged releases:

- Patch releases fix bugs without source-breaking API changes.
- Minor releases add backward-compatible APIs or support new Better Auth server capabilities.
- Major releases may remove deprecated APIs or require newer Swift, Xcode, or platform versions.

Until `1.0.0`, public APIs can still change, but releases should keep migration notes focused and explicit.

## Platform Support

The package currently supports:

- iOS 17+
- macOS 14+
- Swift 6 mode

Dropping a supported OS, Swift, or Xcode version requires a minor release before `1.0.0` and a major release after `1.0.0`, unless the old toolchain can no longer build packages accepted by Apple's current developer tooling.

## Release Checklist

Before tagging a release:

1. Run `swift test --enable-swift-testing`.
2. Run `swiftformat . --lint --config .swiftformat`.
3. Run `swiftlint --config .swiftlint.yml --strict`.
4. Run live contract tests against a Better Auth server when credentials are available:

   ```sh
   BETTER_AUTH_CONTRACT_BASE_URL="https://auth.example.com" \
   BETTER_AUTH_CONTRACT_EMAIL="contract-user@example.com" \
   BETTER_AUTH_CONTRACT_PASSWORD="..." \
   swift test --enable-swift-testing --filter LiveBetterAuthContractTests
   ```

5. Tag with `vMAJOR.MINOR.PATCH`.
