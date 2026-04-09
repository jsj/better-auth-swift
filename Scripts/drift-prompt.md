You are analyzing API contract drift between the upstream Better Auth server and the better-auth-swift SDK.

Below are two lists:
1. **UPSTREAM** — all endpoint paths from the Better Auth server source
2. **SDK** — all endpoint paths the Swift SDK currently covers
3. **DIFF** — endpoints in upstream but not in the SDK

Your job is to analyze the diff and produce a structured report.

## Classification rules

Categorize each uncovered upstream endpoint as one of:

- **should-add**: Core auth endpoint that a mobile client SDK should cover (session, email, password, social, OTP, passkey, 2FA, account management)
- **plugin-candidate**: Plugin-specific endpoint that could be a separate Swift module (organization, admin, api-key, SSO)
- **not-relevant**: Server-side infrastructure endpoint not needed in a client SDK (oauth-provider, openapi, OIDC, well-known, callbacks with dynamic segments like `:id`)

## Output format

```markdown
## Contract Drift Report

### New endpoints to add (should-add)
- `/endpoint-path` — brief description of what it does

### Plugin candidates
- `/plugin-name/*` — brief summary of the plugin surface

### Not relevant (server-only)
- `/endpoint-path` — why it's not needed

### Removed or renamed (breaking)
List any endpoints the SDK covers that no longer exist upstream.

### Summary
One paragraph: is the SDK up to date, or does it need work? How urgent?
```

## Data

### UPSTREAM
```
{{UPSTREAM}}
```

### SDK
```
{{SDK}}
```

### DIFF (upstream only)
```
{{DIFF}}
```
