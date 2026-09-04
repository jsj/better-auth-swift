// A local-only contract target: no Hono routes, response adapters, or Cloudflare glue.
import { betterAuth } from 'better-auth';
import { memoryAdapter } from 'better-auth/adapters/memory';
import { bearer } from 'better-auth/plugins';

const port = Number(process.env.BETTER_AUTH_UPSTREAM_PORT ?? 8798);
const baseURL = `http://127.0.0.1:${port}`;
const resetTokens = new Map<string, string>();
const auth = betterAuth({
  baseURL,
  secret: 'local-contract-only-secret-at-least-32-characters',
  database: memoryAdapter({ user: [], session: [], account: [], verification: [] }),
  emailAndPassword: {
    enabled: true,
    async sendResetPassword({ user, token }) {
      resetTokens.set(user.email, token);
    },
  },
  plugins: [bearer()],
  trustedOrigins: [baseURL],
  rateLimit: { enabled: false },
});

Bun.serve({
  hostname: '127.0.0.1',
  port,
  fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === '/health') return Response.json({ ok: true });
    // Test fixture access only; all /api/auth/* requests go straight to upstream.
    if (url.pathname === '/test/reset-token') {
      return Response.json({ token: resetTokens.get(url.searchParams.get('email') ?? '') ?? null });
    }
    return auth.handler(request);
  },
});
console.log(`Unmodified Better Auth handler listening at ${baseURL}`);
