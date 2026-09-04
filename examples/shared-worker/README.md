# Shared example routes

Edit `routes/app.ts` here for both the SwiftUI and UIKit example backends.
Wrangler's build step and each worker's `test` and `typecheck` scripts copy this source into
`src/routes/app.generated.ts`. The generated copy keeps relative imports bound
to that worker's auth configuration and dependencies. It is not committed. Wrangler watches the shared source and local worker source, so edits reload during development.

Run both workers' tests and typechecks after changing the shared routes.
