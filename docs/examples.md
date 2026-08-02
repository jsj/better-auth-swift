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

1. If the environment file does not exist, copy `examples/cf-workers-swiftui/ios/.env.example` to `examples/cf-workers-swiftui/ios/.env`.
2. Start the backend stack from `examples/cf-workers-swiftui` with `npm run dev`.
3. To validate backend behavior, run `npm test` in `examples/cf-workers-swiftui/worker`.
4. Run `npm run typecheck` in the same directory.
5. Open the iOS project under `examples/cf-workers-swiftui/ios`.
6. Run the app with the local base URL.

## UIKit example

- [`examples/cf-workers-uikit`](../examples/cf-workers-uikit)

What is included:

- a UIKit iOS app
- a Worker-based Better Auth backend
- worker tests and typecheck scripts

Suggested local flow:

1. If the environment file does not exist, copy `examples/cf-workers-uikit/ios/.env.example` to `examples/cf-workers-uikit/ios/.env`.
2. Run `npm test` in `examples/cf-workers-uikit/worker`.
3. Run `npm run typecheck` in the same directory.
4. Open the iOS project under `examples/cf-workers-uikit/ios`.
5. Run the app with the local base URL.

## Default local URL

Both example apps default to `http://127.0.0.1:8787` for local development.

## When to use them

Use these examples for a full integration reference. They cover app launch, native Apple sign-in, authenticated requests, and common Better Auth flows.
