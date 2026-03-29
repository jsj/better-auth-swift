# Examples

This repository includes two end-to-end example stacks that use the local package and a Cloudflare Workers backend.

## SwiftUI example

- [`examples/cf-workers-swiftui`](../examples/cf-workers-swiftui)

What is included:

- a SwiftUI iOS app
- a Worker-based Better Auth backend
- a root script for starting the local stack
- worker tests and typecheck scripts

Suggested local flow:

1. Copy `examples/cf-workers-swiftui/ios/.env.example` to `examples/cf-workers-swiftui/ios/.env` if needed.
2. Start the backend stack from `examples/cf-workers-swiftui` with `npm run dev`.
3. In `examples/cf-workers-swiftui/worker`, run `npm test` and `npm run typecheck` when validating backend behavior.
4. Open the iOS project under `examples/cf-workers-swiftui/ios` and run the app against the local base URL.

## UIKit example

- [`examples/cf-workers-uikit`](../examples/cf-workers-uikit)

What is included:

- a UIKit iOS app
- a Worker-based Better Auth backend
- worker tests and typecheck scripts

Suggested local flow:

1. Copy `examples/cf-workers-uikit/ios/.env.example` to `examples/cf-workers-uikit/ios/.env` if needed.
2. In `examples/cf-workers-uikit/worker`, run `npm test` and `npm run typecheck`.
3. Open the iOS project under `examples/cf-workers-uikit/ios` and run the app against the local base URL.

## Default local URL

Both example apps default to `http://127.0.0.1:8787` for local development.

## When to use them

Use these examples when you want a full integration reference for app launch restore, native Apple sign-in, authenticated requests, and common Better Auth flows rather than isolated SDK snippets.
