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

## Current state (as of April 2026)

All five original roadmap phases are implemented. The SDK ships 108 tests across two test targets with zero failures.

Implemented areas include:

- session persistence, restoration, refresh, and authenticated requests
- SwiftUI state management via `AuthStore` with typed launch state
- reinstall-aware Keychain restore with explicit restore result model
- app-launch bootstrap semantics
- deep-link and callback helpers for OAuth, magic link, and email verification
- email/password sign up and sign in
- password reset and password change flows
- username availability and username sign in
- native Apple sign in exchange
- social sign in and generic OAuth
- anonymous auth with upgrade to permanent account
- magic link flows
- email OTP flows
- phone OTP flows
- two-factor auth flows, including enable, disable, TOTP, OTP, and backup codes
- passkey registration, authentication, listing, update, and deletion
- email verification and change email flows
- linked account flows
- session and device session management
- account deletion with optional password confirmation
- re-authentication for sensitive operations
- JWT and JWKS helpers
- organization plugin module (CRUD, members, invitations, active org)

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

## Completed phases (1-5)

Phases 1 through 5 of the original roadmap are implemented and merged to main:

1. **Stabilize current breadth** — normalized the auth surface, aligned tests and examples
2. **Native differentiators** — reinstall-aware restore, launch state, callback helpers
3. **Account lifecycle** — delete user, anonymous upgrade, re-authentication
4. **Security and session control** — 2FA disable, hardened revocation and error tests
5. **Plugin expansion** — organization plugin module validating the extension pattern

108 tests across two targets, zero failures.

## Phase 6: Polish

Goal: make the shipped work visible and reliable.

- README rewrite reflecting full SDK surface
- CI coverage for all test targets including the organization plugin
- XcodeGen project and release workflow updated for the organization module
- Roadmap updated to current state

## Phase 7: Upstream sync automation

Goal: detect when upstream Better Auth changes affect the Swift SDK.

Candidate approach: a scheduled agent that diffs the upstream `better-auth` source against the SDK's endpoint contracts and model shapes, then flags breaking changes or new plugin opportunities.

This is deferred until the tooling story (GitHub Actions, Claude Code triggers, or similar) is clearer.

## Open questions

1. How should the SDK track upstream Better Auth endpoint additions and breaking changes?
2. Which additional plugins should get dedicated Swift targets next (admin, api-key, SSO)?
3. Should the SwiftUI layer grow into richer view components or stay as a thin observable wrapper?
- expand into plugins through a clean extension model
