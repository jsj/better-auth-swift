# better-auth-swift SDK Roadmap Spec

Status: living reference

## Purpose

This document is the durable product and implementation reference for the Swift SDK roadmap.

It is meant to:

- capture the current state of the SDK
- define the product direction in plain language
- organize roadmap work into implementation phases
- give future coding sessions a stable source of truth
- break large goals into smaller specs over time

The intent is not to chase endpoint parity for its own sake. The intent is to make Better Auth feel first-class and deeply native on Apple platforms.

## North star

Build a feature-complete, native-first Better Auth client for Apple platforms.

Success means:

- Better Auth works naturally in iPhone, iPad, and Mac apps
- the SDK covers the major auth flows developers expect
- the SDK provides native UX advantages beyond generic web wrappers
- app teams can start simple and grow into advanced auth features without replacing their client stack

## Current state

The repository already appears broader than the public README suggests.

Current implemented areas include:

- session persistence, restoration, refresh, and authenticated requests
- SwiftUI state management via `AuthStore`
- email/password sign up and sign in
- password reset and password change flows
- username availability and username sign in
- native Apple sign in exchange
- social sign in and generic OAuth
- anonymous auth
- magic link flows
- email OTP flows
- phone OTP flows
- two-factor auth flows, including backup codes
- passkey registration, authentication, listing, update, and deletion
- email verification and change email flows
- linked account flows
- session and device session management
- JWT and JWKS helpers

This means the near-term roadmap should emphasize productization, polish, and native differentiation more than raw breadth.

## Product principles

### 1. Native first

The SDK should feel designed for Apple app development rather than adapted from a browser client.

Examples:

- first-class Keychain support
- app lifecycle aware restore behavior
- native Apple sign-in flows
- clean deep-link and callback handling
- SwiftUI-friendly state primitives

### 2. Security by default

The safest reasonable behavior should be the default.

Examples:

- secure token persistence
- clear session expiration handling
- explicit re-auth for sensitive operations
- strong passkey and 2FA support
- predictable session revocation semantics

### 3. Progressive onboarding

Apps should be able to start users fast, then upgrade them into stronger account states later.

Examples:

- anonymous auth first
- later upgrade to Apple, passkey, social, or email
- account linking without losing app data

### 4. Plugin aware

Better Auth is broader than core auth. The Swift SDK should not hardcode every plugin, but it should make plugin support realistic and maintainable.

### 5. Operationally clear

Developers should be able to understand what state the SDK is in and what it is doing.

Examples:

- explicit restore semantics
- meaningful auth events
- reliable error surfaces
- examples that mirror production flows

## What this roadmap is optimizing for

This roadmap prioritizes:

1. strengthening what is already implemented
2. shipping obvious native Apple-platform advantages
3. making account lifecycle flows feel complete
4. creating a clean path for future plugin expansion

This roadmap does not prioritize:

- chasing every Better Auth feature immediately
- building broad plugin coverage before the extension story is clear
- adding multiple overlapping APIs without stronger state semantics

## Roadmap themes

## Theme 1: Stabilize and expose the real SDK surface

The current SDK surface appears broader than what a new user would infer from the README and examples.

Desired outcome:

- implemented capabilities are easy to discover
- naming, models, and errors feel consistent
- examples and tests reflect the actual product surface

Candidate work:

- produce a feature coverage matrix against the Better Auth client surface
- align examples with currently implemented auth methods
- align tests with every supported flow where practical
- document supported flows and platform assumptions
- tighten auth status and state transition semantics

Why this matters:

A broad SDK that looks narrow will be undervalued. Stabilization turns hidden breadth into visible product strength.

## Theme 2: Native differentiators

This is the most important differentiator theme.

Desired outcome:

- the Swift SDK is not merely feature-capable, it is the best-feeling native Better Auth client

Candidate work:

- reinstall-aware session restoration using Keychain persistence
- optional synchronizable storage behavior where appropriate
- app-launch restore semantics that are explicit and predictable
- helpers for deep-link, callback, and token handoff flows
- native wrappers for common Apple auth entry points

Why this matters:

This is where the SDK can be better than generic wrappers and better aligned with what Apple developers expect.

## Theme 3: Account lifecycle completeness

Desired outcome:

- users can start quickly and evolve into durable accounts without friction or data loss

Candidate work:

- anonymous auth as a first-class onboarding path
- upgrade anonymous users into permanent accounts
- link additional auth methods to existing accounts
- require re-auth for sensitive actions
- standardize flows for email change, account deletion, and session-sensitive operations

Why this matters:

Firebase has long been strong at anonymous-to-permanent upgrade flows. This is a high-value mobile pattern and a strong reference point.

## Theme 4: Security and device management

Desired outcome:

- the SDK feels production-grade for account and session security

Candidate work:

- session list and device session polish
- revoke current, other, or all sessions with clear semantics
- active device session switching polish
- passkey management UX helpers
- 2FA management polish, including backup and recovery flows

Why this matters:

A mature auth SDK is not only about signing in. It is also about lifecycle control after sign-in.

## Theme 5: Extensibility and plugin parity

Desired outcome:

- the SDK can grow with Better Auth without becoming brittle

Candidate work:

- define extension points for plugin-specific endpoints and models
- establish a pattern for shipping plugin modules or optional surfaces
- identify first plugin targets based on user value and implementation fit

Likely early plugin candidates:

- SSO
- organization or team flows
- admin or elevated account operations
- API key or machine-oriented auth helpers

Why this matters:

Plugin support should be systematic. The SDK should avoid one-off additions that create long-term inconsistency.

## Phased roadmap

## Phase 1: Stabilize current breadth

Goal:

Turn the current broad implementation into a clearly shaped, reliable SDK surface.

Deliverables:

- verify and normalize the implemented auth surface
- create a feature coverage matrix
- align examples, tests, and public messaging with actual capabilities
- tighten state, error, and event semantics where needed

Exit criteria:

- the SDK surface is internally coherent
- feature support is discoverable
- there is confidence that implemented flows behave consistently

## Phase 2: Ship native differentiators

Goal:

Make the SDK feel unmistakably native on Apple platforms.

Deliverables:

- reinstall-aware restore strategy
- optional Keychain synchronization strategy where appropriate
- explicit app-launch restoration states
- OAuth, magic link, and OTP callback helpers

Exit criteria:

- app teams can implement native restore and callback flows with minimal custom glue
- the SDK clearly improves on web-wrapper ergonomics

Detailed reference:

- `SPECS/native-differentiators-v0.2.md`

## Phase 3: Complete account lifecycle flows

Goal:

Support the full journey from lightweight onboarding to durable account ownership.

Deliverables:

- anonymous-to-permanent account upgrade patterns
- account linking flows
- re-auth flows for sensitive operations
- stronger guidance and examples for lifecycle-sensitive transitions

Exit criteria:

- apps can onboard quickly without forcing immediate account creation
- users can safely upgrade and link accounts without losing continuity

## Phase 4: Production-grade security and session control

Goal:

Make post-sign-in security and session management a first-class part of the SDK.

Deliverables:

- device/session management polish
- robust passkey management flows
- robust 2FA management flows
- clearer semantics for revocation and active-session behavior

Exit criteria:

- the SDK supports operationally mature account security use cases
- session control feels deliberate and complete

## Phase 5: Plugin expansion model

Goal:

Create a repeatable way to expand with the Better Auth ecosystem.

Deliverables:

- extension architecture for plugin-specific capability
- first plugin prioritization list
- first plugin implementation specs once the extension story is stable

Exit criteria:

- plugin support can grow without fragmenting the SDK design

## Recommended implementation order

If work is split into focused coding sessions, the order should be:

1. feature audit and stability pass
2. reinstall-aware restore and launch semantics
3. anonymous upgrade and account linking
4. deep-link and callback helpers
5. security and device/session polish
6. plugin extension architecture
7. first plugin implementations

## Candidate follow-up specs

This file should stay high level. The following should be broken into their own specs when implementation starts:

- `SPECS/reinstall-aware-restore.md`
- `SPECS/feature-coverage-matrix.md`
- `SPECS/anonymous-upgrade-flows.md`
- `SPECS/account-linking-and-reauth.md`
- `SPECS/deep-link-callback-helpers.md`
- `SPECS/session-device-management.md`
- `SPECS/plugin-extension-architecture.md`

## Competitive references

### Firebase

Useful reference ideas:

- anonymous auth as a strong onboarding pattern
- upgrade and linking flows that preserve user continuity
- durable device identity via Keychain-backed restoration behavior

Takeaway:

Firebase is a strong benchmark for lifecycle completeness and low-friction onboarding.

### Supabase Swift

Useful reference ideas:

- explicit auth state changes and session lifecycle behavior
- broad auth method coverage
- PKCE and mobile OAuth ergonomics
- SSO and identity linking patterns

Takeaway:

Supabase is a strong benchmark for state semantics, breadth, and auth system shape.

## Open questions

These questions should be resolved as the roadmap is implemented:

1. How much should reinstall recovery rely on default Keychain persistence versus explicit opt-in synchronization behavior?
2. What auth state model should be exposed publicly for launch and restore flows?
3. Which plugin category should be first once the extension architecture is ready?
4. How opinionated should the SwiftUI state layer become versus keeping the core SDK primitive and flexible?
5. Which flows require dedicated native helpers rather than staying at the raw request-model layer?

## Working rule for future sessions

When future coding sessions use this spec, they should:

- choose one roadmap theme or sub-problem
- produce a focused implementation spec for that area
- implement the smallest useful slice
- validate the result with tests and examples
- update this roadmap if priorities or assumptions change

## Summary

The roadmap should not be framed as “add more endpoints.”

It should be framed as:

- stabilize the already broad SDK surface
- ship native Apple-platform differentiators
- complete account lifecycle flows
- strengthen security and session control
- expand into plugins through a clean extension model
