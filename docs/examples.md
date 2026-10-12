# Examples

This repository includes two end-to-end example stacks that use the local package and a Cloudflare Workers backend.

## SwiftUI example

- [`examples/cf-workers-swiftui`](../examples/cf-workers-swiftui)

The example includes:

- a SwiftUI iOS app
- a Worker-based Better Auth backend
- a root script for starting the local stack
- worker tests and typecheck scripts

Local procedure:

1. If the environment file does not exist, copy `examples/cf-workers-swiftui/ios/.env.example` to `examples/cf-workers-swiftui/ios/.env`.
2. Start the backend stack from `examples/cf-workers-swiftui` with `npm run dev`.
3. Run `npm test` in `examples/cf-workers-swiftui/worker`.
4. Run `npm run typecheck` in the same directory.
5. Open the iOS project under `examples/cf-workers-swiftui/ios`.
6. Run the app with the local base URL.

## UIKit example

- [`examples/cf-workers-uikit`](../examples/cf-workers-uikit)

The example includes:

- a UIKit iOS app
- a Worker-based Better Auth backend
- worker tests and typecheck scripts

Local procedure:

1. If the environment file does not exist, copy `examples/cf-workers-uikit/ios/.env.example` to `examples/cf-workers-uikit/ios/.env`.
2. Run `npm test` in `examples/cf-workers-uikit/worker`.
3. Run `npm run typecheck` in the same directory.
4. Open the iOS project under `examples/cf-workers-uikit/ios`.
5. Run the app with the local base URL.

## Default local URL

Both example apps default to `http://127.0.0.1:8787` for local development.

## Backend versions

Both workers use Better Auth 1.7.7 and `better-auth-cloudflare` 0.4.0.
The SwiftUI stack uses API Emulator 0.9.0 and provider plugins 0.12.1.
The worker dependencies include Hono 4.13.13, JOSE 6.2.12, and Drizzle 0.45.4.
The development dependencies include Wrangler 4.149.0, Workers types 5, and Vitest 4.1.11.

The examples preserve the SDK routes for generic OAuth sign-in and account links.
The workers send these requests to the current Better Auth social endpoints.
The workers translate `providerId` to `provider` and preserve OAuth state cookies.
The Swift endpoint defaults remain unchanged.

Migration `0002_remove_account_issuer.sql` removes the obsolete required `issuer` column.
The migration preserves existing accounts and sessions.
The migration rejects duplicate provider and account identities before it changes the schema.
New databases require both migrations.

## Local database upgrade

1. Keep `0001_init.sql` unchanged.
2. From either worker directory, run the migration command:

```sh
npx wrangler d1 migrations apply DB --local
```

3. Start the updated worker.

## Existing deployment upgrade

1. Export a backup of the D1 database.
2. Restore the backup to a separate database.
3. Run this query on the restored database to identify duplicate account identities:

```sql
SELECT provider_id, account_id, COUNT(*) AS account_count
FROM account
GROUP BY provider_id, account_id
HAVING COUNT(*) > 1;
```

4. If the query returns duplicates, resolve the account ownership conflicts before migration.
5. Run the migration on the restored database.
6. Run the authentication tests against the restored database.
7. Pause authentication writes to the deployment database.
8. Apply the migration to the deployment database.
9. Deploy the updated worker dependencies.
10. Restart every worker instance.
11. Request new Magic Links for incomplete sign-ins.
12. Restart incomplete OAuth sign-ins.

After migration, a package downgrade alone cannot restore the old schema.
The [account migration guide](https://better-auth.com/blog/1-7-account-schema) explains database recovery requirements.
The [Magic Link security advisory](https://github.com/better-auth/better-auth/security/advisories/GHSA-965c-763c-88jm) explains the security fixes.

## KV configuration

These examples use D1 without KV secondary storage.
Cloudflare integration 0.4 requires compatible storage for verification and rate limits.

If you add KV, configure database storage for verification:
`verification: { storeInDatabase: true }`.

If you add KV, configure database storage for rate limits:
`rateLimit: { storage: "database" }`.

## When to use them

Use these examples for a full integration reference. They cover app launch, native Apple sign-in, authenticated requests, and common Better Auth flows.
