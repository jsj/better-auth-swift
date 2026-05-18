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

1. Run the release verifier:

   ```sh
   Scripts/verify_release.sh --version vMAJOR.MINOR.PATCH
   ```

2. For release candidates, require a configured live Better Auth backend:

   ```sh
   BETTER_AUTH_CONTRACT_BASE_URL="https://auth.example.com" \
   BETTER_AUTH_CONTRACT_EMAIL="contract-user@example.com" \
   BETTER_AUTH_CONTRACT_PASSWORD="..." \
   Scripts/verify_release.sh --version vMAJOR.MINOR.PATCH --require-live-contracts
   ```

   The verifier runs:

   - `swift build -c release`
   - `swift test --enable-swift-testing`
   - public symbol graph guard for the exported `BetterAuth` API surface
   - `swiftformat . --lint --config .swiftformat`
   - `swiftlint --config .swiftlint.yml --strict`
   - live contract tests when Better Auth contract credentials are configured

   The repository also includes a deterministic local fixture backend runner:

   ```sh
   Scripts/run_local_contracts.sh
   ```

   This starts the Cloudflare Workers example with a fresh local D1 database,
   provisions a contract user through the fixture capture endpoint, and runs the
   live contract suite with email/session lifecycle, JWKS, and anonymous account
   coverage enabled.

   Live contract tests can also be run directly:

   ```sh
   BETTER_AUTH_CONTRACT_BASE_URL="https://auth.example.com" \
   BETTER_AUTH_CONTRACT_EMAIL="contract-user@example.com" \
   BETTER_AUTH_CONTRACT_PASSWORD="..." \
   swift test --enable-swift-testing --filter LiveBetterAuthContractTests
   ```

   Optional contract coverage can be enabled with:

   - `BETTER_AUTH_CONTRACT_USERNAME` and `BETTER_AUTH_CONTRACT_USERNAME_PASSWORD`
   - `BETTER_AUTH_CONTRACT_EXPECT_JWKS=true`
   - `BETTER_AUTH_CONTRACT_SUPPORTS_ANONYMOUS=true`

   For the repository's Cloudflare Workers fixture backend, the email/password
   contract can self-provision its configured user before sign-in:

   - `BETTER_AUTH_CONTRACT_PROVISION_WITH_FIXTURES=true`
   - `BETTER_AUTH_CONTRACT_FIXTURE_CAPTURE_URL` when the capture endpoint is not
     `${BETTER_AUTH_CONTRACT_BASE_URL}/api/fixtures/captures`

3. Confirm GitHub Actions is green for the release commit.
4. Tag with `vMAJOR.MINOR.PATCH`.
