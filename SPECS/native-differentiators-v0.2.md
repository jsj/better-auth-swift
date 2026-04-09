# Native Differentiators / v0.2

Status: planned
Parent roadmap: `SPECS/sdk-roadmap.md`

## Goal

Make `better-auth-swift` feel better on Apple platforms than generic web-client wrappers.

This phase is about turning the SDK's existing auth breadth into obvious native product value.

## Scope

Phase 2 focuses on four related workstreams:

1. reinstall-aware keychain restore
2. better app-launch restoration semantics
3. deep-link and callback helpers for OAuth, magic links, and URL-driven verification flows
4. light native integration polish for SwiftUI and UIKit/AppKit entry points

## Why this phase exists

The SDK already has a broad auth surface, but the most important Apple-platform advantage is not raw endpoint count.

It is the launch and callback experience:

- how well auth state survives app restarts and reinstall scenarios
- how easy it is to bootstrap auth at app launch
- how little manual glue app teams need for `onOpenURL`, callback parsing, and token handoff

If this phase succeeds, the SDK will feel intentionally native rather than merely portable.

## Current code baseline

The current codebase already includes some of the right building blocks:

- `BetterAuthConfiguration.SessionStorage` supports `accessibility`, `accessGroup`, and `synchronizable`
- `BetterAuthSessionManager.restoreOrRefreshSession()` is the recommended session bootstrap path
- `BetterAuthSessionManager.handle(_ url)` already handles generic OAuth callbacks by parsing `code`, `state`, and provider information
- auth request models already expose `callbackURL` in multiple places, including social sign-in, generic OAuth, magic link, email verification, and change email flows
- `AuthStore` already exposes a simple async `restore()` entry point

However, these pieces do not yet form a clear native-first product surface.

Current gaps:

- restore has no typed outcome model beyond optional session and thrown error
- launch semantics are not explicit enough for root-view bootstrapping
- OAuth callback handling is log-oriented and not result-oriented
- magic-link and related callback flows still require app-level URL parsing glue
- there is no obvious recommended integration shape for SwiftUI `.onOpenURL` or app-launch bootstrapping

## Non-goals

Phase 2 should not expand into unrelated roadmap themes.

Out of scope for this phase:

- plugin work
- new auth providers
- anonymous-to-permanent upgrade flows
- account linking and re-auth
- session/device management polish
- large UI abstraction layers

Those belong to later phases.

## Success criteria

Phase 2 is successful when:

- apps can bootstrap auth state at launch with an explicit, typed state model
- reinstall-aware restore behavior is deliberate and well-defined
- supported callback URLs can be handled with one SDK call instead of custom parsing
- the SDK preserves backward compatibility where practical while introducing stronger native primitives
- example apps can demonstrate launch restore and callback handling with minimal custom glue

## Workstream A: Reinstall-aware keychain restore

### Problem

Apple apps often rely on Keychain persistence to preserve auth continuity across app launches and, in some cases, app reinstall on the same device.

The SDK already uses a Keychain-backed session store by default, but the behavior is not yet framed as a first-class restore strategy.

### Goals

- make restore behavior explicit and predictable
- preserve continuity when valid keychain-backed credentials survive reinstall
- avoid destructive session clearing on transient launch-time failures
- let app developers choose between device-local and synchronizable storage behavior intentionally

### Proposed deliverables

- add a typed restore result model in the core SDK
- define restore provenance and refresh outcome explicitly
- document and test how local keychain persistence differs from optional synchronizable storage
- preserve the existing convenience API while layering it over the richer result model

### Proposed API direction

Illustrative only; exact naming can change.

```swift
public enum BetterAuthRestoreResult: Sendable, Equatable {
    case noStoredSession
    case restored(
        BetterAuthSession,
        source: BetterAuthRestoreSource,
        refresh: BetterAuthRefreshDisposition
    )
    case cleared(BetterAuthRestoreClearReason)
}

public enum BetterAuthRestoreSource: Sendable, Equatable {
    case memory
    case keychain
}

public enum BetterAuthRefreshDisposition: Sendable, Equatable {
    case notNeeded
    case refreshed
    case deferredBecauseOffline
}
```

Possible new entry point:

```swift
public func restoreSessionOnLaunch() async throws -> BetterAuthRestoreResult
```

The existing `restoreOrRefreshSession()` can remain as a convenience wrapper.

### Required behavior rules

- if a valid session exists in memory, use it
- if no in-memory session exists, try keychain restore
- if the restored session is near expiry, attempt refresh
- if refresh fails due to an invalid or revoked session, clear local state and surface a typed clear result
- if refresh fails for a recoverable network reason, do not eagerly destroy local state; surface the outcome explicitly so the app can decide UI policy
- synchronizable storage remains opt-in, not default

### Acceptance criteria

- same-device restore from surviving keychain state is a deliberate supported path
- transient network failures at launch do not silently sign the user out
- invalid or revoked sessions are cleared consistently
- developers can select local-only versus synchronizable storage behavior intentionally
- tests cover no-session, restored, refreshed, offline-deferred, and cleared flows

### First implementation slice

1. introduce `BetterAuthRestoreResult` and the underlying restore path
2. preserve `restoreOrRefreshSession()` as a convenience wrapper
3. add unit tests around restore semantics and clearing policy

## Workstream B: App-launch restoration semantics

### Problem

`AuthStore` currently exposes `session`, `isLoading`, and `statusMessage`, but that is not enough to drive a polished launch or splash flow.

App teams need to distinguish between:

- initial app boot
- in-progress restore
- authenticated launch
- signed-out launch
- recoverable restore issues
- fatal restore issues

### Goals

- make root-view bootstrapping straightforward
- let SwiftUI apps model launch state explicitly
- expose richer restore outcomes without forcing every app to build its own state machine

### Proposed deliverables

- add an explicit launch/bootstrap state to `AuthStore`
- optionally expose the last restore result alongside the simplified launch state
- add a single recommended app-launch entry point for SwiftUI apps
- provide example integration patterns for UIKit/AppKit as well

### Proposed API direction

Illustrative only; exact naming can change.

```swift
public enum AuthLaunchState: Sendable, Equatable {
    case idle
    case restoring
    case authenticated(BetterAuthSession)
    case unauthenticated
    case recoverableFailure
    case failed
}
```

Potential store additions:

```swift
public private(set) var launchState: AuthLaunchState
public private(set) var lastRestoreResult: BetterAuthRestoreResult?

public func bootstrap() async
```

### Behavioral rules

- `bootstrap()` should be the recommended launch path for `AuthStore`
- `launchState` should be sufficient to drive a root view without relying on string messages
- `statusMessage` can remain for diagnostics, but should not be the primary state signal
- `session` should stay synchronized with successful restore outcomes

### Acceptance criteria

- a SwiftUI app can drive launch UI from `launchState` alone
- the SDK can distinguish between signed-out and temporarily recoverable restore outcomes
- example apps no longer need ad hoc launch-loading logic

### First implementation slice

1. add `launchState` and `lastRestoreResult` to `AuthStore`
2. add `bootstrap()` backed by the new restore result model
3. update one example app to use the new launch state

## Workstream C: Deep-link and callback helpers

### Problem

The SDK already knows how to complete generic OAuth callbacks, but the current API is too low-level for a great native integration story.

Today:

- `handle(_ url)` only covers generic OAuth callback parsing
- it logs internally instead of returning a typed result
- magic-link verification still requires app code to extract tokens and construct requests manually
- there is no unified parser for incoming auth URLs

### Goals

- support one-call handling for supported auth callback URLs
- return typed results instead of relying on side effects and logs
- reduce app-level parsing code for OAuth and magic-link style flows
- make unsupported URLs easy to ignore safely

### Proposed deliverables

- add a parse-only URL routing API
- add a handle-and-apply URL API returning a typed result
- support generic OAuth callbacks first
- support magic-link callback handling next
- support any other URL-driven verification flows once the backend contract is confirmed

### Proposed API direction

Illustrative only; exact naming can change.

```swift
public enum BetterAuthIncomingURL: Sendable, Equatable {
    case genericOAuth(GenericOAuthCallbackRequest)
    case magicLink(MagicLinkVerifyRequest)
    case unsupported
}

public enum BetterAuthHandledURLResult: Sendable, Equatable {
    case genericOAuth(BetterAuthSession)
    case magicLink(MagicLinkVerificationResult)
    case ignored
}

public func parseIncomingURL(_ url: URL) -> BetterAuthIncomingURL
public func handleIncomingURL(_ url: URL) async throws -> BetterAuthHandledURLResult
```

Potential store helper:

```swift
public func handleIncomingURL(_ url: URL) async
```

### Behavioral rules

- the parser should safely ignore unrelated app URLs
- OAuth callback handling must return a typed result instead of only logging
- magic-link callbacks should not require manual query-item extraction in app code
- URL-dispatched verification flows are in scope; manual code-entry OTP flows remain on the existing request-model path

### Acceptance criteria

- a SwiftUI `.onOpenURL` handler can call one SDK method for supported auth URLs
- OAuth completion returns a typed result to the caller
- magic-link verification can be driven directly from an incoming URL for supported backend shapes
- unsupported URLs are ignored cleanly

### First implementation slice

1. replace or wrap the current OAuth-only `handle(_ url)` path with a typed result API
2. introduce `parseIncomingURL(_:)`
3. add magic-link route support
4. add unit tests for supported and ignored URL shapes

## Workstream D: Native integration polish

### Problem

Even with better restore and callback APIs, app developers still need a recommended integration shape.

### Goals

- make the correct integration pattern obvious
- keep helpers lightweight and framework-friendly
- avoid introducing heavy UI abstractions

### Proposed deliverables

- add lightweight helpers for SwiftUI and UIKit/AppKit integration points
- define a recommended callback filtering strategy for app URLs
- ensure examples show the preferred launch and callback flow

### Candidate additions

- `AuthStore.handleIncomingURL(_:)`
- a small callback-filter configuration object if needed
- sample `SwiftUI.App` integration using `.task` and `.onOpenURL`
- sample UIKit or AppKit integration using app/scene delegate hooks

### Acceptance criteria

- the preferred integration path is obvious from examples and API shape
- apps do not need a custom URL parser for supported flows
- the phase improves ergonomics without introducing a UI framework inside the SDK

## Milestone plan

### Milestone 1: Restore foundation

Deliver:

- typed restore result model
- explicit restore clearing rules
- non-destructive offline semantics

### Milestone 2: Launch-state integration

Deliver:

- `AuthStore` bootstrap state
- `lastRestoreResult`
- one example app updated to the new launch model

### Milestone 3: OAuth callback handling

Deliver:

- parse-only URL router
- typed handle-and-apply OAuth callback result
- backward-compatible migration path from the current `handle(_ url)` entry point

### Milestone 4: Magic-link and URL-driven verification helpers

Deliver:

- magic-link route handling
- support for additional URL-driven verification flows where the backend contract is confirmed
- example app callback integration polish

## Recommended implementation order

1. core restore result and restore semantics
2. `AuthStore` launch/bootstrap state
3. typed OAuth callback handling
4. generic incoming URL parser
5. magic-link callback handling
6. example app integration and polish

## Definition of done

Phase 2 is done when:

- restore behavior is explicit and tested
- launch bootstrapping has a recommended typed state model
- supported callback URLs can be routed through one SDK entry point
- the examples demonstrate the intended Apple-platform integration path
- the SDK feels meaningfully more native than a generic Better Auth HTTP wrapper

## Open questions

1. Should the richer restore API live alongside `restoreOrRefreshSession()` permanently, or should the older API eventually become a compatibility wrapper only?
2. What exact restore outcome should be surfaced for offline launch with an otherwise valid cached session?
3. Which incoming URL shapes are guaranteed by Better Auth across OAuth, magic-link, and verification flows?
4. Do we need a callback filtering configuration object, or is a parse-and-ignore API sufficient?
5. Which example app should become the canonical reference for `.task` plus `.onOpenURL` integration?

## First follow-up specs after this one

Once implementation starts, Phase 2 can be split further into:

- `SPECS/reinstall-aware-restore.md`
- `SPECS/deep-link-callback-helpers.md`
- `SPECS/auth-launch-state.md`

## Summary

Phase 2 should be treated as a product-shaping phase, not a transport-layer phase.

The work is not "add more auth methods."

The work is:

- preserve user continuity more intelligently
- make launch state obvious
- make callback handling one-call and typed
- make the Apple-platform integration path feel first-class
