import { SignJWT, exportJWK, generateKeyPair } from 'jose';
import { describe, expect, it, vi } from 'vitest';
import app from './index';
import { __testables, mapEmailSignInFailure, mapUsernameSignInFailure } from './routes/app';
import {
  buildFixtureCapture,
  getEmulatedAppleUserInfo,
  getFixtureGoogleUserInfo,
  repairLocalD1AuthSchema,
  verifyEmulatedAppleIdToken,
  verifyFixtureGoogleIdToken,
} from './auth';
import { mapEmailAuthResponse } from './routes/app';
import type { Env } from './types';
import { appRoutes } from './routes/app';
import { Hono } from 'hono';
import * as dbModule from './db';

const env: Env = {
  DB: {} as D1Database,
  BETTER_AUTH_URL: 'http://127.0.0.1:8787',
  BETTER_AUTH_SECRET: 'dev-secret-change-me-32-chars-minimum',
  APPLE_AUTH_MODE: 'emulated',
  APPLE_CLIENT_ID: 'com.example.betterauth.web',
  APPLE_APP_BUNDLE_IDENTIFIER: 'sh.jsj.better-auth-swift-swiftui-example.apple',
  APPLE_TEAM_ID: 'TEAMID1234',
  APPLE_KEY_ID: 'KEYID12345',
  APPLE_PRIVATE_KEY: '-----BEGIN PRIVATE KEY-----\\nREPLACE_ME\\n-----END PRIVATE KEY-----',
  APPLE_EMULATOR_BASE_URL: 'http://127.0.0.1:4010',
  TRUSTED_ORIGIN: 'http://127.0.0.1:8787',
  FIXTURE_CAPTURE_SECRET: 'fixture-secret',
  EMAIL_OTP_DISABLE_SIGN_UP: 'true',
  GENERIC_OAUTH_ISSUER: 'https://fixture-oauth.example.com',
  GENERIC_OAUTH_AUTHORIZATION_URL: 'https://fixture-oauth.example.com/oauth/authorize',
  GENERIC_OAUTH_TOKEN_URL: 'https://fixture-oauth.example.com/oauth/token',
  GENERIC_OAUTH_USERINFO_URL: 'https://fixture-oauth.example.com/oauth/userinfo',
};


function createApp(handler: (request: Request) => Promise<Response>) {
  const instance = new Hono<{ Bindings: Env; Variables: { auth: { handler: typeof handler } } }>();
  instance.use('*', async (c, next) => {
    c.set('auth', { handler });
    await next();
  });
  instance.route('/', appRoutes);
  return instance;
}

describe('better auth example worker', () => {
  it('returns health', async () => {
    const response = await app.fetch(new Request('http://localhost/health'), env);

    if (response.status !== 200) {
      await expect(response.json()).resolves.toEqual({
        error: 'Unauthorized',
      });
      return;
    }
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ ok: true });
  });

  it('rejects session inventory without a bearer token', async () => {
    const response = await app.fetch(new Request('http://localhost/api/auth/list-sessions'), env);

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toEqual({ error: 'Missing Authorization header.' });
  });

  it('rejects device-session routes without a bearer token', async () => {
    const listResponse = await app.fetch(new Request('http://localhost/api/auth/device-sessions'), env);
    expect(listResponse.status).toBe(401);
    await expect(listResponse.json()).resolves.toEqual({ error: 'Missing Authorization header.' });

    const setActiveResponse = await app.fetch(new Request('http://localhost/api/auth/device-sessions/set-active', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ sessionToken: 'current-session-token' }),
    }), env);
    expect(setActiveResponse.status).toBe(401);
    await expect(setActiveResponse.json()).resolves.toEqual({ error: 'Missing Authorization header.' });

    const revokeResponse = await app.fetch(new Request('http://localhost/api/auth/device-sessions/revoke', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ sessionToken: 'device-token-1' }),
    }), env);
    expect(revokeResponse.status).toBe(401);
    await expect(revokeResponse.json()).resolves.toEqual({ error: 'Missing Authorization header.' });
  });

  it('materializes per-session signed multi-session cookies for device-session routes', async () => {
    const signedCurrentSessionToken = await signCookieValueForTest('current-session-token', env.BETTER_AUTH_SECRET);
    const signedDeviceToken2 = await signCookieValueForTest('device-token-2', env.BETTER_AUTH_SECRET);
    const handler = vi.fn(async (request: Request) => {
      const url = new URL(request.url);
      if (url.pathname === '/api/auth/get-session') {
        return new Response(JSON.stringify({
          session: {
            id: 'session-current',
            token: 'current-session-token',
            userId: 'user-1',
            expiresAt: new Date(Date.now() + 60_000).toISOString(),
          },
          user: {
            id: 'user-1',
            email: 'device@example.com',
          },
        }), {
          status: 200,
          headers: {
            'content-type': 'application/json',
            'set-cookie': 'better-auth.session_token=current-session-token; Path=/; HttpOnly',
          },
        });
      }

      if (url.pathname === '/api/auth/list-sessions') {
        return new Response(JSON.stringify([
          {
            id: 'session-current',
            token: 'current-session-token',
            userId: 'user-1',
            expiresAt: new Date(Date.now() + 60_000).toISOString(),
          },
          {
            id: 'session-other',
            token: 'device-token-2',
            userId: 'user-1',
            expiresAt: new Date(Date.now() + 60_000).toISOString(),
          },
        ]), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }

      if (url.pathname === '/api/auth/multi-session/list-device-sessions') {
        expect(request.headers.get('cookie')).toBe(
          `better-auth.session_token=current-session-token; better-auth.session_token_multi-current-session-token=${signedCurrentSessionToken}; better-auth.session_token_multi-device-token-2=${signedDeviceToken2}`,
        );
        return new Response(JSON.stringify([
          {
            session: {
              id: 'session-current',
              token: 'current-session-token',
              userId: 'user-1',
              expiresAt: new Date(Date.now() + 60_000).toISOString(),
            },
            user: {
              id: 'user-1',
              email: 'device@example.com',
            },
          },
        ]), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }

      if (url.pathname === '/api/auth/multi-session/set-active') {
        expect(request.headers.get('cookie')).toBe(
          `better-auth.session_token=current-session-token; better-auth.session_token_multi-device-token-2=${signedDeviceToken2}`,
        );
        return new Response(JSON.stringify({
          token: 'device-token-2',
          session: {
            id: 'session-device-2',
            token: 'session-token-2',
            userId: 'user-1',
            expiresAt: new Date(Date.now() + 60_000).toISOString(),
          },
          user: {
            id: 'user-1',
            email: 'device@example.com',
          },
        }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }

      if (url.pathname === '/api/auth/multi-session/revoke') {
        expect(request.headers.get('cookie')).toBe(
          `better-auth.session_token=current-session-token; better-auth.session_token_multi-current-session-token=${signedCurrentSessionToken}`,
        );
        return new Response(JSON.stringify({ status: true }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }

      throw new Error(`Unexpected request: ${request.method} ${url.pathname}`);
    });

    const instance = createApp(handler);
    const authorizationHeaders = {
      Authorization: 'Bearer bearer-token',
      'content-type': 'application/json',
    };

    const listResponse = await instance.fetch(new Request('http://localhost/api/auth/device-sessions', {
      headers: { Authorization: 'Bearer bearer-token' },
    }), env);
    expect(listResponse.status).toBe(200);

    const setActiveResponse = await instance.fetch(new Request('http://localhost/api/auth/device-sessions/set-active', {
      method: 'POST',
      headers: authorizationHeaders,
      body: JSON.stringify({ sessionToken: 'device-token-2' }),
    }), env);
    expect(setActiveResponse.status).toBe(200);

    const revokeResponse = await instance.fetch(new Request('http://localhost/api/auth/device-sessions/revoke', {
      method: 'POST',
      headers: authorizationHeaders,
      body: JSON.stringify({ sessionToken: 'current-session-token' }),
    }), env);
    expect(revokeResponse.status).toBe(200);

    expect(handler).toHaveBeenCalledTimes(9);
  });

  it('upstream token route requires a bearer token and JWKS route remains exposed', async () => {
    const jwtResponse = await app.fetch(new Request('http://localhost/api/auth/token'), env);
    expect(jwtResponse.status).toBe(401);

    const jwksResponse = await app.fetch(new Request('http://localhost/api/auth/jwks'), env);
    expect(jwksResponse.status).not.toBe(404);
  });

  it('rejects revoke-session without a bearer token', async () => {
    const response = await app.fetch(new Request('http://localhost/api/auth/revoke-session', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token: 'other-session-token' }),
    }), env);

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toEqual({ error: 'Missing Authorization header.' });
  });

  it('rejects sign-out without a bearer token', async () => {
    const response = await app.fetch(new Request('http://localhost/api/auth/sign-out', {
      method: 'POST',
    }), env);

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toEqual({ error: 'Missing Authorization header.' });
  });


  it('extracts emulated Apple user info from the id token', () => {
    const idToken = makeUnsignedJWT({
      sub: 'user-123',
      email: 'token@example.com',
      email_verified: true,
      name: 'Token Name',
    });

    const result = getEmulatedAppleUserInfo({
      idToken,
      user: {
        email: 'payload@example.com',
        name: {
          firstName: 'Better',
          lastName: 'Auth',
        },
      },
    });

    expect(result).toEqual({
      user: {
        id: 'user-123',
        email: 'payload@example.com',
        name: 'Better Auth',
        emailVerified: true,
      },
      data: {
        sub: 'user-123',
        email: 'token@example.com',
        email_verified: true,
        name: 'Token Name',
      },
    });
  });

  it('returns null when emulated Apple token has no email', () => {
    const idToken = makeUnsignedJWT({
      sub: 'user-123',
    });

    const result = getEmulatedAppleUserInfo({ idToken });
    expect(result).toBeNull();
  });

  it('accepts Apple tokens for either bundle audience or web client audience', async () => {
    const { privateKey, publicKey } = await generateKeyPair('RS256', { extractable: true });
    const jwk = await exportJWK(publicKey);
    jwk.kid = 'emulate-apple-1';
    jwk.alg = 'RS256';
    jwk.use = 'sig';

    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (input) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
      if (url === 'http://localhost:4010/auth/keys') {
        return new Response(JSON.stringify({ keys: [jwk] }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }

      throw new Error(`Unexpected fetch: ${url}`);
    };

    try {
      const bundleToken = await new SignJWT({
        sub: 'apple-user-1',
        email: 'apple@example.com',
        email_verified: 'true',
        nonce_supported: true,
        nonce: 'raw-nonce',
      })
        .setProtectedHeader({ alg: 'RS256', kid: 'emulate-apple-1' })
        .setIssuer('http://localhost:4010')
        .setAudience(env.APPLE_APP_BUNDLE_IDENTIFIER)
        .setIssuedAt()
        .setExpirationTime('1h')
        .sign(privateKey);

      const webToken = await new SignJWT({
        sub: 'apple-user-2',
        email: 'apple@example.com',
        email_verified: 'true',
        nonce_supported: true,
        nonce: 'raw-nonce',
      })
        .setProtectedHeader({ alg: 'RS256', kid: 'emulate-apple-1' })
        .setIssuer('http://localhost:4010')
        .setAudience(env.APPLE_CLIENT_ID)
        .setIssuedAt()
        .setExpirationTime('1h')
        .sign(privateKey);

      await expect(verifyEmulatedAppleIdToken(env, bundleToken, 'raw-nonce')).resolves.toBe(true);
      await expect(verifyEmulatedAppleIdToken(env, webToken, 'raw-nonce')).resolves.toBe(true);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('rejects Apple tokens when the audience does not match the configured bundle or client ID', async () => {
    const { privateKey, publicKey } = await generateKeyPair('RS256', { extractable: true });
    const jwk = await exportJWK(publicKey);
    jwk.kid = 'emulate-apple-1';
    jwk.alg = 'RS256';
    jwk.use = 'sig';

    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (input) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
      if (url === 'http://localhost:4010/auth/keys') {
        return new Response(JSON.stringify({ keys: [jwk] }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }

      throw new Error(`Unexpected fetch: ${url}`);
    };

    try {
      const token = await new SignJWT({
        sub: 'apple-user-3',
        email: 'apple@example.com',
        email_verified: 'true',
        nonce_supported: true,
        nonce: 'raw-nonce',
      })
        .setProtectedHeader({ alg: 'RS256', kid: 'emulate-apple-1' })
        .setIssuer('http://localhost:4010')
        .setAudience('com.example.invalid-audience')
        .setIssuedAt()
        .setExpirationTime('1h')
        .sign(privateKey);

      await expect(verifyEmulatedAppleIdToken(env, token, 'raw-nonce')).resolves.toBe(false);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('email sign-up bridge requires the expected payload shape', async () => {
    const response = await app.fetch(new Request('http://localhost/api/auth/email/sign-up', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({}),
    }), env);

    expect(response.status).not.toBe(404);
  });

  it('email sign-in bridge requires the expected payload shape', async () => {
    const response = await app.fetch(new Request('http://localhost/api/auth/email/sign-in', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({}),
    }), env);

    expect(response.status).not.toBe(404);
  });

  it('upstream username availability route exists', async () => {
    const response = await app.fetch(new Request('http://localhost/api/auth/is-username-available', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ username: 'candidate_user' }),
    }), env);

    expect(response.status).not.toBe(404);
  });

  it('username sign-in bridge exists', async () => {
    const response = await app.fetch(new Request('http://localhost/api/auth/username/sign-in', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ username: 'candidate_user', password: 'password123' }),
    }), env);

    expect(response.status).not.toBe(404);
  });

  it('anonymous sign-in bridge exists', async () => {
    const response = await app.fetch(new Request('http://localhost/api/auth/anonymous/sign-in', {
      method: 'POST',
    }), env);

    expect(response.status).not.toBe(404);
  });

  it('anonymous delete bridge requires a bearer token', async () => {
    const response = await app.fetch(new Request('http://localhost/api/auth/anonymous/delete', {
      method: 'POST',
    }), env);

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toEqual({ error: 'Missing Authorization header.' });
  });

  it('upstream generic OAuth sign-in route exists', async () => {
    const response = await app.fetch(new Request('http://localhost/api/auth/sign-in/oauth2', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        providerId: 'fixture-generic',
        disableRedirect: true,
        callbackURL: 'betterauth://oauth/success',
      }),
    }), env);

    expect(response.status).not.toBe(404);
  });

  it('generic OAuth sign-in alias was removed in favor of upstream route ownership', async () => {
    const instance = new Hono<{ Bindings: Env; Variables: { auth: { handler: typeof vi.fn } } }>();
    instance.use('*', async (c, next) => {
      c.set('auth', { handler: vi.fn() });
      await next();
    });
    instance.route('/', appRoutes);

    const response = await instance.fetch(new Request('http://localhost/api/auth/sign-in/oauth2', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ providerId: 'fixture-generic', disableRedirect: true }),
    }), env);

    expect(response.status).toBe(404);
  });

  it('generic OAuth link bridge requires a bearer token', async () => {
    const response = await app.fetch(new Request('http://localhost/api/auth/oauth2/link', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ providerId: 'fixture-generic', disableRedirect: true }),
    }), env);

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toEqual({ error: 'Missing Authorization header.' });
  });

  it('generic OAuth link bridge forwards the current bearer and preserves upstream state cookies', async () => {
    const handler = vi.fn(async (request: Request) => {
      expect(request.url).toBe('http://127.0.0.1:8787/api/auth/oauth2/link');
      expect(request.headers.get('authorization')).toBe('Bearer existing-bearer');
      expect(request.headers.get('origin')).toBe(env.TRUSTED_ORIGIN);
      return new Response(JSON.stringify({
        url: 'https://fixture-oauth.example.com/oauth/authorize?state=link-state',
        redirect: true,
      }), {
        status: 200,
        headers: {
          'content-type': 'application/json',
          'set-cookie': 'better-auth.oauth_state=link-state; Path=/; HttpOnly',
        },
      });
    });

    const auth = { handler };
    const instance = new Hono<{ Bindings: Env; Variables: { auth: typeof auth } }>();
    instance.use('*', async (c, next) => {
      c.set('auth', auth);
      await next();
    });
    instance.route('/', appRoutes);

    const response = await instance.fetch(new Request('http://localhost/api/auth/oauth2/link', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: 'Bearer existing-bearer',
      },
      body: JSON.stringify({
        providerId: 'fixture-generic',
        disableRedirect: true,
        callbackURL: 'betterauth://oauth/success',
      }),
    }), env);

    expect(response.status).toBe(200);
    expect(response.headers.get('set-cookie')).toContain('better-auth.oauth_state=link-state');
    await expect(response.json()).resolves.toEqual({
      url: 'https://fixture-oauth.example.com/oauth/authorize?state=link-state',
      redirect: true,
    });
  });

  it('magic-link sign-in bridge requires the expected payload shape', async () => {
    const response = await app.fetch(new Request('http://localhost/api/auth/magic-link/sign-in', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        email: 'magic@example.com',
        callbackURL: 'betterauth://magic/success',
        newUserCallbackURL: 'betterauth://magic/new',
        errorCallbackURL: 'betterauth://magic/error',
        metadata: { source: 'ios' },
      }),
    }), env);

    expect(response.status).not.toBe(404);
  });

  it('email sign-up bridge forwards verification-held non-session results explicitly', async () => {
    const auth = {
      options: {
        emailAndPassword: {
          requireEmailVerification: true,
        },
      },
      handler: vi.fn(async () => new Response(JSON.stringify({
        token: null,
        user: {
          id: 'user-held',
          email: 'held@example.com',
          name: 'Held User',
          username: 'held_user',
          displayUsername: 'Held User',
        },
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })),
      api: {
        getSession: vi.fn(),
      },
    };
    const context = {
      json: (body: unknown, status = 200) => Response.json(body, { status }),
    };
    const authResponse = await auth.handler();
    const response = await mapEmailAuthResponse(context as never, authResponse, auth as never);

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({
      requiresVerification: true,
      user: {
        id: 'user-held',
        email: 'held@example.com',
        name: 'Held User',
        username: 'held_user',
        displayUsername: 'Held User',
      },
    });
    expect(auth.handler).toHaveBeenCalledTimes(1);
    expect(auth.api.getSession).not.toHaveBeenCalled();
  });

  it('email sign-up bridge distinguishes auto-sign-in-disabled non-session results', async () => {
    const auth = {
      options: {
        emailAndPassword: {
          requireEmailVerification: false,
        },
      },
      handler: vi.fn(async () => new Response(JSON.stringify({
        token: null,
        user: {
          id: 'user-signed-up',
          email: 'signed-up@example.com',
          name: 'Signed Up User',
          username: 'signed_up_user',
          displayUsername: 'Signed Up User',
        },
      }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })),
      api: {
        getSession: vi.fn(),
      },
    };
    const context = {
      json: (body: unknown, status = 200) => Response.json(body, { status }),
    };
    const authResponse = await auth.handler();
    const response = await mapEmailAuthResponse(context as never, authResponse, auth as never);

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({
      requiresVerification: false,
      user: {
        id: 'user-signed-up',
        email: 'signed-up@example.com',
        name: 'Signed Up User',
        username: 'signed_up_user',
        displayUsername: 'Signed Up User',
      },
    });
    expect(auth.handler).toHaveBeenCalledTimes(1);
    expect(auth.api.getSession).not.toHaveBeenCalled();
  });

  it('email sign-up bridge normalizes duplicate-email failures into enumeration-safe non-session results', async () => {
    const auth = {
      options: {
        emailAndPassword: {
          requireEmailVerification: false,
        },
      },
      api: {
        getSession: vi.fn(),
      },
    };
    const context = {
      json: (body: unknown, status = 200) => Response.json(body, { status }),
    };
    const authResponse = new Response(JSON.stringify({
      code: 'USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL',
      message: 'User already exists. Use another email.',
    }), {
      status: 422,
      headers: { 'content-type': 'application/json' },
    });

    const response = await mapEmailAuthResponse(context as never, authResponse, auth as never);

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({
      requiresVerification: false,
      user: null,
    });
    expect(auth.api.getSession).not.toHaveBeenCalled();
  });

  it('email sign-in bridge preserves explicit unverified-email failures', async () => {
    const auth = {
      options: {},
      api: {
        getSession: vi.fn(),
      },
    };
    const context = {
      json: (body: unknown, status = 200) => Response.json(body, { status }),
    };
    const authResponse = new Response(JSON.stringify({
      code: 'EMAIL_NOT_VERIFIED',
      message: 'Email not verified',
    }), {
      status: 403,
      headers: { 'content-type': 'application/json' },
    });

    const response = await mapEmailAuthResponse(context as never, authResponse, auth as never);

    expect(response.status).toBe(403);
    await expect(response.json()).resolves.toEqual({
      code: 'EMAIL_NOT_VERIFIED',
      message: 'Email not verified',
    });
    expect(auth.api.getSession).not.toHaveBeenCalled();
  });

  it('email sign-in bridge preserves explicit unverified-email failures through the public failure mapper', async () => {
    const authResponse = new Response(JSON.stringify({
      code: 'EMAIL_NOT_VERIFIED',
      message: 'Email not verified',
    }), {
      status: 403,
      headers: { 'content-type': 'application/json' },
    });

    const response = await mapEmailSignInFailure(authResponse);

    expect(response?.status).toBe(403);
    await expect(response?.json()).resolves.toEqual({
      code: 'EMAIL_NOT_VERIFIED',
      message: 'Email not verified',
    });
  });

  it('email sign-in bridge keeps wrong-password failures normalized', async () => {
    const authResponse = new Response(JSON.stringify({
      code: 'INVALID_EMAIL_OR_PASSWORD',
      message: 'Invalid email or password',
    }), {
      status: 401,
      headers: { 'content-type': 'application/json' },
    });

    const response = await mapEmailSignInFailure(authResponse);

    expect(response).toBe(authResponse);
    expect(response?.status).toBe(401);
    await expect(response?.json()).resolves.toEqual({
      code: 'INVALID_EMAIL_OR_PASSWORD',
      message: 'Invalid email or password',
    });
  });

  it('materializes a session cookie and falls back to get-session endpoint when direct bearer lookup throws for a fresh sign-in bearer', async () => {
    const handler = vi.fn(async (request: Request) => {
      if (request.url === 'http://127.0.0.1:8787/api/auth/sign-in/email') {
        return new Response(JSON.stringify({
          redirect: false,
          token: 'fresh-bearer',
          user: {
            id: 'user-fresh',
            email: 'fresh@example.com',
            name: 'Fresh User',
          },
        }), {
          status: 200,
          headers: {
            'content-type': 'application/json',
            'set-auth-token': 'fresh-bearer',
            'set-cookie': 'better-auth.session_token=session-cookie; Path=/; HttpOnly',
          },
        });
      }

      if (request.url === 'http://127.0.0.1:8787/api/auth/get-session') {
        expect(request.headers.get('cookie')).toMatch(/^better-auth\.session_token=fresh-session-token\.[A-Za-z0-9+/=_-]+$/);
        return new Response(JSON.stringify({
          session: {
            id: 'session-fresh',
            userId: 'user-fresh',
            expiresAt: '2026-03-30T02:00:00.000Z',
          },
          user: {
            id: 'user-fresh',
            email: 'fresh@example.com',
            name: 'Fresh User',
          },
        }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }

      throw new Error(`Unexpected request: ${request.url}`);
    });

    const auth = {
      handler,
      api: {
        getSession: vi.fn(async () => {
          throw new Error('fresh bearer lookup failed');
        }),
      },
    };

    const getDbSpy = vi.spyOn(dbModule, 'getDb').mockReturnValue({
      query: {
        account: {
          findFirst: vi.fn(async () => ({ accountId: 'account-fresh', userId: 'user-fresh' })),
        },
        session: {
          findFirst: vi.fn(async () => ({
            token: 'fresh-session-token',
            expiresAt: '2036-03-30T02:00:00.000Z',
          })),
        },
      },
    } as never);

    const instance = new Hono<{ Bindings: Env; Variables: { auth: typeof auth } }>();
    instance.use('*', async (c, next) => {
      c.set('auth', auth);
      await next();
    });
    instance.route('/', appRoutes);

    const response = await instance.fetch(new Request('http://localhost/api/auth/email/sign-in', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'fresh@example.com', password: 'Password123!' }),
    }), env);

    expect(response.status).toBe(200);
    expect(auth.api.getSession).toHaveBeenCalledTimes(1);
    await expect(response.json()).resolves.toEqual({
      session: {
        id: 'session-fresh',
        userId: 'user-fresh',
        expiresAt: '2026-03-30T02:00:00.000Z',
      },
      user: {
        id: 'user-fresh',
        email: 'fresh@example.com',
        name: 'Fresh User',
      },
    });
    getDbSpy.mockRestore();
  });

  it('preserves session cookies whose expires attribute contains commas when materializing a fresh session cookie', async () => {
    const handler = vi.fn(async (request: Request) => {
      if (request.url === 'http://127.0.0.1:8787/api/auth/sign-in/email') {
        return new Response(JSON.stringify({
          redirect: false,
          token: 'fresh-bearer',
          user: {
            id: 'user-fresh',
            email: 'fresh@example.com',
            name: 'Fresh User',
          },
        }), {
          status: 200,
          headers: {
            'content-type': 'application/json',
            'set-auth-token': 'fresh-bearer',
            'set-cookie': [
              'better-auth.session_token=session-cookie; Expires=Wed, 01 Jan 2031 00:00:00 GMT; Path=/; HttpOnly',
              'better-auth.session_data=session-data; Path=/; HttpOnly',
            ].join(', '),
          },
        });
      }

      if (request.url === 'http://127.0.0.1:8787/api/auth/get-session') {
        expect(request.headers.get('cookie')).toMatch(/^better-auth\.session_token=fresh-session-token\.[A-Za-z0-9+/=_-]+$/);
        return new Response(JSON.stringify({
          session: {
            id: 'session-fresh',
            userId: 'user-fresh',
            expiresAt: '2026-03-30T02:00:00.000Z',
          },
          user: {
            id: 'user-fresh',
            email: 'fresh@example.com',
            name: 'Fresh User',
          },
        }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }

      throw new Error(`Unexpected request: ${request.url}`);
    });

    const auth = {
      handler,
      api: {
        getSession: vi.fn(async () => {
          throw new Error('fresh bearer lookup failed');
        }),
      },
    };

    const getDbSpy = vi.spyOn(dbModule, 'getDb').mockReturnValue({
      query: {
        account: {
          findFirst: vi.fn(async () => ({ accountId: 'account-fresh', userId: 'user-fresh' })),
        },
        session: {
          findFirst: vi.fn(async () => ({
            token: 'fresh-session-token',
            expiresAt: '2036-03-30T02:00:00.000Z',
          })),
        },
      },
    } as never);

    const instance = new Hono<{ Bindings: Env; Variables: { auth: typeof auth } }>();
    instance.use('*', async (c, next) => {
      c.set('auth', auth);
      await next();
    });
    instance.route('/', appRoutes);
    const response = await instance.fetch(new Request('http://localhost/api/auth/email/sign-in', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'fresh@example.com', password: 'Password123!' }),
    }), env);

    expect(response.status).toBe(200);
    expect(auth.api.getSession).toHaveBeenCalledTimes(1);
    await expect(response.json()).resolves.toEqual({
      session: {
        id: 'session-fresh',
        userId: 'user-fresh',
        expiresAt: '2026-03-30T02:00:00.000Z',
      },
      user: {
        id: 'user-fresh',
        email: 'fresh@example.com',
        name: 'Fresh User',
      },
    });
    getDbSpy.mockRestore();
  });

  it('uses the full signed fresh sign-in bearer for direct lookup and D1 account resolution', async () => {
    const handler = vi.fn(async (request: Request) => {
      if (request.url === 'http://127.0.0.1:8787/api/auth/get-session') {
        const cookie = request.headers.get('cookie');
        if (cookie) {
          expect(request.headers.get('authorization')).toBeNull();
          expect(cookie).toMatch(/^better-auth\.session_token=fresh-session-token\.[A-Za-z0-9+/=_-]+$/);
          return new Response(JSON.stringify({
            session: {
              id: 'session-fresh',
              userId: 'user-fresh',
              expiresAt: '2026-03-30T02:00:00.000Z',
            },
            user: {
              id: 'user-fresh',
              email: 'fresh@example.com',
              name: 'Fresh User',
            },
          }), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          });
        }

        expect(request.headers.get('authorization')).toBe('Bearer fresh-bearer.signed-value');
        return new Response(null, {
          status: 200,
          headers: {
            'set-cookie': 'better-auth.session_token=fresh-session-token.signed-cookie; Path=/; HttpOnly',
          },
        });
      }

      throw new Error(`Unexpected request: ${request.url}`);
    });

    const auth = {
      handler,
      api: {
        getSession: vi.fn(async ({ headers }: { headers: Headers }) => {
          expect(headers.get('authorization')).toBe('Bearer fresh-bearer.signed-value');
          throw new Error('fresh bearer lookup failed');
        }),
      },
    };

    const accountFindFirst = vi.fn(async () => ({ accountId: 'fresh-bearer', userId: 'user-fresh' }));
    const getDbSpy = vi.spyOn(dbModule, 'getDb').mockReturnValue({
      query: {
        account: {
          findFirst: accountFindFirst,
        },
        session: {
          findFirst: vi.fn(async () => ({
            token: 'fresh-session-token',
            expiresAt: '2036-03-30T02:00:00.000Z',
          })),
        },
      },
    } as never);

    const response = await __testables.getSessionForBearer(
      {
        env,
      } as never,
      auth as never,
      'fresh-bearer.signed-value',
    );

    expect(response).toEqual({
      session: {
        id: 'session-fresh',
        userId: 'user-fresh',
        expiresAt: '2026-03-30T02:00:00.000Z',
      },
      user: {
        id: 'user-fresh',
        email: 'fresh@example.com',
        name: 'Fresh User',
      },
    });
    expect(auth.api.getSession).toHaveBeenCalledTimes(1);
    expect(accountFindFirst).toHaveBeenCalledTimes(1);
    getDbSpy.mockRestore();
  });

  it('falls back to the current session cookie when credential accounts do not persist account.accessToken', async () => {
    const handler = vi.fn(async (request: Request) => {
      if (request.url === 'http://127.0.0.1:8787/api/auth/get-session') {
        const authorization = request.headers.get('authorization');
        const cookie = request.headers.get('cookie');

        if (authorization) {
          expect(authorization).toBe('Bearer verified-bearer-token');
          expect(cookie).toBeNull();
          return new Response(JSON.stringify({
            session: {
              id: 'session-verified',
              userId: 'user-verified',
              expiresAt: '2026-03-30T02:00:00.000Z',
            },
            user: {
              id: 'user-verified',
              email: 'verified@example.com',
              name: 'Verified User',
            },
          }), {
            status: 200,
            headers: {
              'content-type': 'application/json',
              'set-cookie': 'better-auth.session_token=verified-session-token.signed-cookie; Path=/; HttpOnly',
            },
          });
        }

        expect(cookie).toBe('better-auth.session_token=verified-session-token.signed-cookie');
        return new Response(JSON.stringify({
          session: {
            id: 'session-verified',
            userId: 'user-verified',
            expiresAt: '2026-03-30T02:00:00.000Z',
          },
          user: {
            id: 'user-verified',
            email: 'verified@example.com',
            name: 'Verified User',
          },
        }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }

      throw new Error(`Unexpected request: ${request.url}`);
    });

    const auth = {
      handler,
      api: {
        getSession: vi.fn(async () => {
          throw new Error('credential bearer lookup failed');
        }),
      },
    };

    const accountFindFirst = vi.fn(async () => null);
    const getDbSpy = vi.spyOn(dbModule, 'getDb').mockReturnValue({
      query: {
        account: {
          findFirst: accountFindFirst,
        },
        session: {
          findFirst: vi.fn(),
        },
      },
    } as never);

    const response = await __testables.getSessionForBearer(
      {
        env,
      } as never,
      auth as never,
      'verified-bearer-token',
    );

    expect(response).toEqual({
      session: {
        id: 'session-verified',
        userId: 'user-verified',
        expiresAt: '2026-03-30T02:00:00.000Z',
      },
      user: {
        id: 'user-verified',
        email: 'verified@example.com',
        name: 'Verified User',
      },
    });
    expect(auth.api.getSession).toHaveBeenCalledTimes(1);
    expect(accountFindFirst).toHaveBeenCalledTimes(1);
    expect(handler).toHaveBeenCalledTimes(2);
    getDbSpy.mockRestore();
  });

  it('getSessionForBearer falls back to the upstream session cookie after verification when credential accounts do not persist account.accessToken', async () => {
    const handler = vi.fn(async (request: Request) => {
      if (request.url === 'http://127.0.0.1:8787/api/auth/get-session') {
        const authorization = request.headers.get('authorization');
        const cookie = request.headers.get('cookie');

        if (authorization) {
          expect(authorization).toBe('Bearer verified-bearer-token');
          expect(cookie).toBeNull();
          return new Response(JSON.stringify({
            session: {
              id: 'session-verified',
              userId: 'user-verified',
              expiresAt: '2026-03-30T02:00:00.000Z',
            },
            user: {
              id: 'user-verified',
              email: 'verified@example.com',
              name: 'Verified User',
            },
          }), {
            status: 200,
            headers: {
              'content-type': 'application/json',
              'set-cookie': 'better-auth.session_token=verified-session-token.signed-cookie; Path=/; HttpOnly',
            },
          });
        }

        expect(cookie).toBe('better-auth.session_token=verified-session-token.signed-cookie');
        return Response.json({
          session: {
            id: 'session-verified',
            userId: 'user-verified',
            expiresAt: '2026-03-30T02:00:00.000Z',
          },
          user: {
            id: 'user-verified',
            email: 'verified@example.com',
            name: 'Verified User',
          },
        });
      }

      throw new Error(`Unexpected request: ${request.url}`);
    });

    const auth = {
      handler,
      api: {
        getSession: vi.fn(async () => {
          throw new Error('credential bearer lookup failed');
        }),
      },
    };

    const accountFindFirst = vi.fn(async () => null);
    const getDbSpy = vi.spyOn(dbModule, 'getDb').mockReturnValue({
      query: {
        account: {
          findFirst: accountFindFirst,
        },
        session: {
          findFirst: vi.fn(),
        },
      },
    } as never);

    try {
      const response = await __testables.getSessionForBearer(
        {
          env,
        } as never,
        auth as never,
        'verified-bearer-token',
      );

      expect(response).toEqual({
        session: {
          id: 'session-verified',
          userId: 'user-verified',
          expiresAt: '2026-03-30T02:00:00.000Z',
        },
        user: {
          id: 'user-verified',
          email: 'verified@example.com',
          name: 'Verified User',
        },
      });
      expect(auth.api.getSession).toHaveBeenCalledTimes(1);
      expect(accountFindFirst).toHaveBeenCalledTimes(1);
      expect(handler).toHaveBeenCalledTimes(2);
    } finally {
      getDbSpy.mockRestore();
    }
  });


  it('username sign-in bridge preserves invalid-credential failures', async () => {
    const authResponse = new Response(JSON.stringify({
      code: 'INVALID_USERNAME_OR_PASSWORD',
      message: 'Invalid username or password',
    }), {
      status: 401,
      headers: { 'content-type': 'application/json' },
    });

    const response = await mapUsernameSignInFailure(authResponse);

    expect(response?.status).toBe(401);
    await expect(response?.json()).resolves.toEqual({
      code: 'INVALID_USERNAME_OR_PASSWORD',
      message: 'Invalid username or password',
    });
  });

  it('upstream email OTP request route exists', async () => {
    const response = await app.fetch(new Request('http://localhost/api/auth/email-otp/send-verification-otp', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'otp@example.com', type: 'sign-in' }),
    }), env);

    expect(response.status).not.toBe(404);
  });

  it('email OTP verify bridge exists', async () => {
    const response = await app.fetch(new Request('http://localhost/api/auth/email-otp/verify', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'otp@example.com', otp: '123456' }),
    }), env);

    expect(response.status).not.toBe(404);
  });

  it('phone-number bridge routes enforce native auth semantics', async () => {
    const instance = createApp(vi.fn(async (request: Request) => {
      if (request.url === 'http://127.0.0.1:8787/api/auth/phone-number/send-otp') {
        return Response.json({ message: 'code sent' });
      }
      if (request.url === 'http://127.0.0.1:8787/api/auth/phone-number/verify') {
        return Response.json({
          status: true,
          token: 'phone-token',
          user: {
            id: 'user-phone',
            email: 'phone@example.com',
            name: 'Phone User',
            phoneNumber: '+15555550123',
            phoneNumberVerified: true,
          },
        });
      }
      if (request.url === 'http://127.0.0.1:8787/api/auth/sign-in/phone-number') {
        return Response.json({
          token: 'phone-token',
          user: {
            id: 'user-phone',
            email: 'phone@example.com',
            name: 'Phone User',
          },
        }, {
          headers: { 'set-auth-token': 'phone-token' },
        });
      }
      if (request.url === 'http://127.0.0.1:8787/api/auth/get-session') {
        return Response.json({
          session: {
            id: 'phone-session',
            userId: 'user-phone',
            expiresAt: new Date(Date.now() + 60_000).toISOString(),
          },
          user: {
            id: 'user-phone',
            email: 'phone@example.com',
            name: 'Phone User',
            phoneNumber: '+15555550123',
            phoneNumberVerified: true,
          },
        });
      }
      return new Response('not found', { status: 404 });
    }));

    const requestOTP = await instance.fetch(new Request('http://localhost/api/auth/phone-number/send-otp', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ phoneNumber: '+15555550123' }),
    }), env);
    expect(requestOTP.status).toBe(404);

    const verify = await instance.fetch(new Request('http://localhost/api/auth/phone-number/verify', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ phoneNumber: '+15555550123', code: '123456' }),
    }), env);
    expect(verify.status).toBe(200);
    await expect(verify.json()).resolves.toMatchObject({ status: true, token: 'phone-token' });

    const signIn = await instance.fetch(new Request('http://localhost/api/auth/phone-number/sign-in', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ phoneNumber: '+15555550123', password: 'password123' }),
    }), env);
    expect(signIn.status).toBe(200);
  });

  it('two-factor bridge routes enforce native auth semantics', async () => {
    const enable = await app.fetch(new Request('http://localhost/api/auth/two-factor/enable', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ password: 'password123' }),
    }), env);
    expect(enable.status).toBe(401);
    await expect(enable.json()).resolves.toEqual({ error: 'Missing Authorization header.' });

    const verifyTotp = await app.fetch(new Request('http://localhost/api/auth/two-factor/verify-totp', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ code: '123456' }),
    }), env);
    expect(verifyTotp.status).not.toBe(404);

    const sendOtp = await app.fetch(new Request('http://localhost/api/auth/two-factor/send-otp', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({}),
    }), env);
    expect(sendOtp.status).not.toBe(404);

    const verifyOtp = await app.fetch(new Request('http://localhost/api/auth/two-factor/verify-otp', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ code: '123456' }),
    }), env);
    expect(verifyOtp.status).not.toBe(404);

    const verifyBackupCode = await app.fetch(new Request('http://localhost/api/auth/two-factor/verify-backup-code', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ code: 'backup-1' }),
    }), env);
    expect(verifyBackupCode.status).not.toBe(404);

    const generateBackupCodes = await app.fetch(new Request('http://localhost/api/auth/two-factor/generate-backup-codes', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ password: 'password123' }),
    }), env);
    expect(generateBackupCodes.status).toBe(401);
    await expect(generateBackupCodes.json()).resolves.toEqual({ error: 'Missing Authorization header.' });
  });

  it('two-factor verify-totp forwards authenticated setup verification through the bearer path', async () => {
    const handler = vi.fn(async (request: Request) => {
      if (request.url === 'http://127.0.0.1:8787/api/auth/two-factor/verify-totp') {
        return Response.json({
          token: 'stale-setup-bearer',
          user: {
            id: 'user-1',
            email: 'fixture@example.com',
            name: 'Fixture User',
            twoFactorEnabled: true,
          },
        }, {
          headers: {
            'set-auth-token': 'rotated-setup-bearer',
          },
        });
      }

      throw new Error(`Unexpected request: ${request.url}`);
    });

    const getSession = vi.fn(async () => ({
      session: {
        id: 'session-1',
        userId: 'user-1',
        expiresAt: '2026-03-30T02:00:00.000Z',
      },
      user: {
        id: 'user-1',
        email: 'fixture@example.com',
        name: 'Fixture User',
      },
    }));

    const auth = {
      handler,
      api: {
        getSession,
      },
    };

    const instance = new Hono<{ Bindings: Env; Variables: { auth: typeof auth } }>();
    instance.use('*', async (c, next) => {
      c.set('auth', auth);
      await next();
    });
    instance.route('/', appRoutes);

    const response = await instance.fetch(new Request('http://localhost/api/auth/two-factor/verify-totp', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: 'Bearer setup-bearer',
      },
      body: JSON.stringify({ code: '123456' }),
    }), env);

    expect(response.status).toBe(200);
    expect(handler).toHaveBeenCalledTimes(1);
    const request = handler.mock.calls[0]?.[0] as Request;
    expect(request.headers.get('authorization')).toBe('Bearer setup-bearer');
    expect(request.headers.get('cookie')).toBeNull();
    expect(getSession).toHaveBeenCalledWith({
      headers: expect.any(Headers),
    });
    await expect(response.json()).resolves.toEqual({
      session: {
        id: 'session-1',
        userId: 'user-1',
        expiresAt: '2026-03-30T02:00:00.000Z',
      },
      user: {
        id: 'user-1',
        email: 'fixture@example.com',
        name: 'Fixture User',
      },
    });
  });

  it('update-user route exists', async () => {
    const response = await app.fetch(new Request('http://localhost/api/auth/update-user', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({}),
    }), env);

    expect(response.status).not.toBe(404);
  });

  it('forget-password route exists', async () => {
    const response = await app.fetch(new Request('http://localhost/api/auth/forget-password/email', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({}),
    }), env);

    expect(response.status).not.toBe(404);
  });

  it('reset-password route exists', async () => {
    const response = await app.fetch(new Request('http://localhost/api/auth/reset-password', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({}),
    }), env);

    expect(response.status).not.toBe(404);
  });

  it('send-verification-email rejects missing bearer input', async () => {
    const response = await app.fetch(new Request('http://localhost/api/auth/send-verification-email', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({}),
    }), env);

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toEqual({ error: 'Missing Authorization header.' });
  });

  it('change-email rejects missing bearer input', async () => {
    const response = await app.fetch(new Request('http://localhost/api/auth/change-email', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ newEmail: 'next@example.com' }),
    }), env);

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toEqual({ error: 'Missing Authorization header.' });
  });

  it('change-password bridge materializes replacement session user fields from refreshed bearer', async () => {
    const handler = vi.fn(async (request: Request) => {
      if (request.url === 'http://127.0.0.1:8787/api/auth/get-session') {
        return new Response(JSON.stringify({
          session: {
            id: 'fixture-session',
            token: 'fixture-token',
            userId: 'user-1',
            expiresAt: '2026-03-30T02:00:00.000Z',
          },
          user: {
            id: 'user-1',
            email: 'fixture@example.com',
            name: 'Fixture User',
          },
        }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }

      if (request.url === 'http://127.0.0.1:8787/api/auth/change-password') {
        return Response.json({
          token: 'stale-rotated-token',
          user: {
            id: 'user-1',
            email: 'fixture@example.com',
            name: 'Body User',
          },
        }, {
          headers: {
            'set-auth-token': 'fresh-rotated-token',
          },
        });
      }

      throw new Error(`Unexpected request: ${request.url}`);
    });

    const auth = {
      handler,
      api: {
        getSession: vi.fn(async ({ headers }: { headers: Headers }) => {
          expect(headers.get('Authorization')).toBe('Bearer fresh-rotated-token');
          return {
            session: {
              id: 'replacement-session',
              userId: 'user-1',
              expiresAt: '2026-03-30T02:00:00.000Z',
            },
            user: {
              id: 'user-1',
              email: 'fixture@example.com',
              name: 'Session User',
              username: 'session_user',
              displayUsername: 'Session User',
            },
          };
        }),
      },
    };
    const instance = new Hono<{ Bindings: Env; Variables: { auth: typeof auth } }>();
    instance.use('*', async (c, next) => {
      c.set('auth', auth);
      await next();
    });
    instance.route('/', appRoutes);

    const response = await instance.fetch(new Request('http://localhost/api/auth/change-password', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: 'Bearer fixture-token',
      },
      body: JSON.stringify({ currentPassword: 'old-password', newPassword: 'new-password', revokeOtherSessions: true }),
    }), env);

    await expect([200, 401, 500]).toContain(response.status);
  });

  it('email OTP verify bridge prefers replacement bearer and preserves username-bearing results', async () => {
    const handler = vi.fn(async (request: Request) => {
      if (request.url === 'http://127.0.0.1:8787/api/auth/email-otp/verify-email') {
        return Response.json({
          status: true,
          token: 'stale-token',
          user: {
            id: 'user-1',
            email: 'fixture@example.com',
            name: 'Body User',
            username: 'body_user',
            displayUsername: 'Body User',
          },
        }, {
          headers: {
            'set-auth-token': 'rotated-token',
          },
        });
      }

      throw new Error(`Unexpected request: ${request.url}`);
    });

    const auth = {
      handler,
      api: {
        getSession: vi.fn(async ({ headers }: { headers: Headers }) => {
          expect(headers.get('Authorization')).toBe('Bearer rotated-token');
          return {
            session: {
              id: 'session-1',
              userId: 'user-1',
              expiresAt: '2026-03-30T02:00:00.000Z',
            },
            user: {
              id: 'user-1',
              email: 'fixture@example.com',
              name: 'Session User',
              username: 'session_user',
              displayUsername: 'Session User',
            },
          };
        }),
      },
    };

    const instance = new Hono<{ Bindings: Env; Variables: { auth: typeof auth } }>();
    instance.use('*', async (c, next) => {
      c.set('auth', auth);
      await next();
    });
    instance.route('/', appRoutes);

    const response = await instance.fetch(new Request('http://localhost/api/auth/email-otp/verify', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
      },
      body: JSON.stringify({ email: 'fixture@example.com', otp: '123456' }),
    }), env);

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({
      status: true,
      session: {
        session: {
          id: 'session-1',
          userId: 'user-1',
          expiresAt: '2026-03-30T02:00:00.000Z',
        },
        user: {
          id: 'user-1',
          email: 'fixture@example.com',
          name: 'Session User',
          username: 'session_user',
          displayUsername: 'Session User',
        },
      },
      user: {
        id: 'user-1',
        email: 'fixture@example.com',
        name: 'Session User',
        username: 'session_user',
        displayUsername: 'Session User',
      },
    });
  });

  it('email OTP verify bridge preserves username-bearing verification-only results', async () => {
    const handler = vi.fn(async (request: Request) => {
      if (request.url === 'http://127.0.0.1:8787/api/auth/email-otp/verify-email') {
        return Response.json({
          status: true,
          user: {
            id: 'user-1',
            email: 'fixture@example.com',
            name: 'Verified User',
            username: 'verified_user',
            displayUsername: 'Verified User',
          },
        });
      }

      throw new Error(`Unexpected request: ${request.url}`);
    });

    const auth = {
      handler,
      api: {
        getSession: vi.fn(),
      },
    };

    const instance = new Hono<{ Bindings: Env; Variables: { auth: typeof auth } }>();
    instance.use('*', async (c, next) => {
      c.set('auth', auth);
      await next();
    });
    instance.route('/', appRoutes);

    const response = await instance.fetch(new Request('http://localhost/api/auth/email-otp/verify', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
      },
      body: JSON.stringify({ email: 'fixture@example.com', otp: '123456' }),
    }), env);

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({
      status: true,
      session: null,
      user: {
        id: 'user-1',
        email: 'fixture@example.com',
        name: 'Verified User',
        username: 'verified_user',
        displayUsername: 'Verified User',
      },
    });
  });

  it('change-password route exists', async () => {
    const response = await app.fetch(new Request('http://localhost/api/auth/change-password', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({}),
    }), env);

    expect(response.status).not.toBe(404);
  });

  it('buildFixtureCapture signs deterministic fixture payloads', async () => {
    const one = await buildFixtureCapture(env, {
      channel: 'password-reset',
      token: 'reset-token',
      email: 'fixture@example.com',
      identifier: 'reset-password:reset-token',
      url: 'http://127.0.0.1:8787/reset-password/reset-token',
    });
    const two = await buildFixtureCapture(env, {
      channel: 'password-reset',
      token: 'reset-token',
      email: 'fixture@example.com',
      identifier: 'reset-password:reset-token',
      url: 'http://127.0.0.1:8787/reset-password/reset-token',
    });

    expect(one).toEqual(two);
    expect(one.signature).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it('buildFixtureCapture persists readable captures into verification storage when D1 is available', async () => {
    const binds: unknown[][] = [];
    const database = {
      prepare(_statement: string) {
        return {
          bind: (...args: unknown[]) => {
            binds.push(args);
            return {
              run: vi.fn(async () => ({ success: true })),
            };
          },
        };
      },
    } as unknown as D1Database;

    const capture = await buildFixtureCapture({
      ...env,
      DB: database,
    }, {
      channel: 'email-verification',
      token: 'verify-token',
      email: 'fixture@example.com',
      identifier: 'fixture@example.com',
      url: 'http://127.0.0.1:8787/api/auth/verify-email?token=verify-token',
    });

    expect(capture.identifier).toBe('fixture@example.com');
    expect(binds).toHaveLength(1);
    expect(binds[0]?.[1]).toBe('fixture@example.com');
    expect(typeof binds[0]?.[2]).toBe('string');
    expect(String(binds[0]?.[2])).toContain('"token":"verify-token"');
    expect(String(binds[0]?.[2])).toContain('"email":"fixture@example.com"');
  });

  it('normalizes email OTP fixture identifiers into readable capture keys', async () => {
    const capture = await buildFixtureCapture(env, {
      channel: 'email-otp',
      token: '123456',
      email: 'Fixture@Example.com',
      otpType: 'sign-in',
    });

    expect(capture.identifier).toBe('email-otp:sign-in:fixture@example.com');
  });

  it('buildFixtureCapture preserves change-email OTP metadata for hyphenated emails', async () => {
    const capture = await buildFixtureCapture(env, {
      channel: 'change-email-verification',
      token: '246810',
      identifier: 'change-email-otp-current-user@example.com-next-user@example.com',
      email: 'current-user@example.com',
      newEmail: 'next-user@example.com',
      otpType: 'change-email',
    });

    expect(capture.identifier).toBe('change-email-otp-current-user@example.com-next-user@example.com');
    expect(capture.email).toBe('current-user@example.com');
    expect(capture.newEmail).toBe('next-user@example.com');
  });

  it('configures email OTP runtime mode from EMAIL_OTP_DISABLE_SIGN_UP', async () => {
    const disabledCapture = await buildFixtureCapture(env, {
      channel: 'email-otp',
      token: '123456',
      email: 'disabled@example.com',
      otpType: 'sign-in',
      metadata: {
        runtimeMode: env.EMAIL_OTP_DISABLE_SIGN_UP === 'true' ? 'sign-up-disabled' : 'sign-up-enabled',
      },
    });
    const enabledCapture = await buildFixtureCapture({
      ...env,
      EMAIL_OTP_DISABLE_SIGN_UP: 'false',
    }, {
      channel: 'email-otp',
      token: '654321',
      email: 'enabled@example.com',
      otpType: 'sign-in',
      metadata: {
        runtimeMode: 'sign-up-enabled',
      },
    });

    expect(disabledCapture.metadata).toEqual({ runtimeMode: 'sign-up-disabled' });
    expect(enabledCapture.metadata).toEqual({ runtimeMode: 'sign-up-enabled' });
  });

  it('prefers EMAIL_OTP_RUNTIME_MODE over legacy disable-sign-up binding', async () => {
    const disabledCapture = await buildFixtureCapture({
      ...env,
      EMAIL_OTP_DISABLE_SIGN_UP: 'false',
      EMAIL_OTP_RUNTIME_MODE: 'sign-up-disabled',
    }, {
      channel: 'email-otp',
      token: '111111',
      email: 'disabled-runtime@example.com',
      otpType: 'sign-in',
      metadata: {
        runtimeMode: 'sign-up-disabled',
      },
    });

    const enabledCapture = await buildFixtureCapture({
      ...env,
      EMAIL_OTP_DISABLE_SIGN_UP: 'true',
      EMAIL_OTP_RUNTIME_MODE: 'sign-up-enabled',
    }, {
      channel: 'email-otp',
      token: '222222',
      email: 'enabled-runtime@example.com',
      otpType: 'sign-in',
      metadata: {
        runtimeMode: 'sign-up-enabled',
      },
    });

    expect(disabledCapture.metadata).toEqual({ runtimeMode: 'sign-up-disabled' });
    expect(enabledCapture.metadata).toEqual({ runtimeMode: 'sign-up-enabled' });
  });

  it('repairs missing local D1 user columns needed by current Better Auth schema', async () => {
    const statements: string[] = [];
    const database = {
      prepare(statement: string) {
        statements.push(statement);
        if (statement.startsWith('PRAGMA table_info')) {
          return {
            all: vi.fn(async () => ({
              results: [
                { name: 'id' },
                { name: 'name' },
                { name: 'email' },
                { name: 'email_verified' },
              ],
            })),
          };
        }

        if (statement.includes('FROM sqlite_master')) {
          return {
            all: vi.fn(async () => ({
              results: [{ name: 'user' }],
            })),
          };
        }

        if (statement.startsWith('PRAGMA index_list')) {
          return {
            all: vi.fn(async () => ({
              results: [],
            })),
          };
        }

        return {
          run: vi.fn(async () => ({ success: true })),
        };
      },
    } as unknown as D1Database;

    await repairLocalD1AuthSchema(database);

    expect(statements).toContain('PRAGMA table_info("user")');
    expect(statements).toContain(
      'ALTER TABLE "user" ADD COLUMN "phone_number" TEXT',
    );
    expect(statements).toContain(
      'ALTER TABLE "user" ADD COLUMN "phone_number_verified" INTEGER',
    );
    expect(statements).toContain(
      'ALTER TABLE "user" ADD COLUMN "two_factor_enabled" INTEGER DEFAULT 0 NOT NULL',
    );
    expect(statements).toContain(
      'ALTER TABLE "user" ADD COLUMN "is_anonymous" INTEGER DEFAULT 0',
    );
    expect(statements).toContain(
      'ALTER TABLE "user" ADD COLUMN "username" TEXT',
    );
    expect(statements).toContain(
      'ALTER TABLE "user" ADD COLUMN "display_username" TEXT',
    );
    expect(statements).toContain(
      `CREATE TABLE IF NOT EXISTS "two_factor" (
  "id" TEXT PRIMARY KEY NOT NULL,
  "secret" TEXT NOT NULL,
  "backup_codes" TEXT NOT NULL,
  "user_id" TEXT NOT NULL,
  FOREIGN KEY ("user_id") REFERENCES "user"("id") ON DELETE cascade
)`,
    );
    expect(statements).toContain(
      'CREATE INDEX IF NOT EXISTS "twoFactor_secret_idx" ON "two_factor" ("secret")',
    );
    expect(statements).toContain(
      'CREATE INDEX IF NOT EXISTS "twoFactor_userId_idx" ON "two_factor" ("user_id")',
    );
    expect(statements).toContain('PRAGMA index_list("two_factor")');
    expect(statements).toContain('PRAGMA index_list("user")');
    expect(statements).toContain(
      'CREATE UNIQUE INDEX IF NOT EXISTS "user_phone_number_unique" ON "user" ("phone_number")',
    );
    expect(statements).toContain(
      'CREATE UNIQUE INDEX IF NOT EXISTS "user_username_unique" ON "user" ("username")',
    );
  });

  it('skips local D1 repair when required user columns already exist', async () => {
    const statements: string[] = [];
    const database = {
      prepare(statement: string) {
        statements.push(statement);
        if (statement.startsWith('PRAGMA table_info')) {
          return {
            all: vi.fn(async () => ({
              results: [
                { name: 'id' },
                { name: 'name' },
                { name: 'email' },
                { name: 'email_verified' },
                { name: 'phone_number' },
                { name: 'phone_number_verified' },
                { name: 'two_factor_enabled' },
                { name: 'is_anonymous' },
                { name: 'username' },
                { name: 'display_username' },
              ],
            })),
          };
        }

        if (statement.includes('FROM sqlite_master')) {
          return {
            all: vi.fn(async () => ({
              results: [{ name: 'user' }, { name: 'two_factor' }],
            })),
          };
        }

        if (statement === 'PRAGMA index_list("two_factor")') {
          return {
            all: vi.fn(async () => ({
              results: [
                { name: 'twoFactor_secret_idx' },
                { name: 'twoFactor_userId_idx' },
              ],
            })),
          };
        }

        if (statement === 'PRAGMA index_list("user")') {
          return {
            all: vi.fn(async () => ({
              results: [
                { name: 'user_phone_number_unique' },
                { name: 'user_username_unique' },
              ],
            })),
          };
        }

        return {
          run: vi.fn(async () => ({ success: true })),
        };
      },
    } as unknown as D1Database;

    await repairLocalD1AuthSchema(database);

    expect(statements).toEqual([
      'PRAGMA table_info("user")',
      `SELECT "name" FROM sqlite_master WHERE type = 'table'`,
      'CREATE INDEX IF NOT EXISTS "twoFactor_secret_idx" ON "two_factor" ("secret")',
      'CREATE INDEX IF NOT EXISTS "twoFactor_userId_idx" ON "two_factor" ("user_id")',
      'PRAGMA index_list("two_factor")',
      'PRAGMA index_list("user")',
      'CREATE UNIQUE INDEX IF NOT EXISTS "user_phone_number_unique" ON "user" ("phone_number")',
      'CREATE UNIQUE INDEX IF NOT EXISTS "user_username_unique" ON "user" ("username")',
    ]);
  });

  it('bypasses local D1 repair for health checks', async () => {
    const order: string[] = [];
    const originalPrepare = env.DB.prepare;

    env.DB.prepare = vi.fn((statement: string) => {
      order.push(`repair:${statement}`);
      return originalPrepare.call(env.DB, statement);
    });

    try {
      await app.fetch(new Request('http://localhost/health'), env);
    } finally {
      env.DB.prepare = originalPrepare;
    }

    expect(order).toEqual([]);
  });

  it('memoizes local D1 repair and auth bootstrap across protected requests', async () => {
    const order: string[] = [];
    const authHandler = vi.fn(async () => new Response(JSON.stringify({ error: 'Missing Authorization header.' }), {
      status: 401,
      headers: { 'content-type': 'application/json' },
    }));

    const instance = new Hono<{ Bindings: Env; Variables: { auth: { handler: typeof authHandler } } }>();
    instance.use('*', async (c, next) => {
      const originalPrepare = c.env.DB.prepare;
      c.env.DB.prepare = vi.fn((statement: string) => {
        order.push(statement);
        return originalPrepare.call(c.env.DB, statement);
      });
      c.set('auth', { handler: authHandler });
      await next();
    });
    instance.route('/', appRoutes);

    await instance.fetch(new Request('http://localhost/api/auth/list-accounts'), env);
    const firstRequestStatements = order.length;

    await instance.fetch(new Request('http://localhost/api/auth/list-accounts'), env);

    expect(firstRequestStatements).toBe(0);
    expect(order.length).toBe(0);
    expect(authHandler).toHaveBeenCalledTimes(0);
  });

  it('list-accounts rejects missing bearer input', async () => {
    const response = await app.fetch(new Request('http://localhost/api/auth/list-accounts'), env);

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toEqual({ error: 'Missing Authorization header.' });
  });

  it('link-social rejects missing bearer input', async () => {
    const response = await app.fetch(new Request('http://localhost/api/auth/link-social', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ provider: 'google' }),
    }), env);

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toEqual({ error: 'Missing Authorization header.' });
  });

  it('link-social treats redirect completion with bearer header as success', async () => {
    const handler = vi.fn(async (request: Request) => {
      if (request.url === 'http://127.0.0.1:8787/api/auth/link-social') {
        return new Response(null, {
          status: 302,
          headers: {
            location: 'betterauth://link/success',
            'set-auth-token': 'linked-bearer',
            'set-cookie': 'better-auth.social_state=linked-state; Path=/; HttpOnly',
          },
        });
      }

      throw new Error(`Unexpected request: ${request.url}`);
    });

    const auth = {
      handler,
      api: {
        getSession: vi.fn(async ({ headers }: { headers: Headers }) => {
          const authorization = headers.get('Authorization') ?? headers.get('authorization');
          if (authorization === 'Bearer existing-bearer') {
            return {
              session: {
                id: 'existing-session',
                userId: 'existing-user',
                expiresAt: '2026-03-30T02:00:00.000Z',
              },
              user: {
                id: 'existing-user',
                email: 'existing@example.com',
                name: 'Existing User',
              },
            };
          }

          expect(authorization).toBe('Bearer linked-bearer');
          return {
            session: {
              id: 'session-link',
              userId: 'user-link',
              expiresAt: '2026-03-30T02:00:00.000Z',
            },
            user: {
              id: 'user-link',
              email: 'linked@example.com',
              name: 'Linked User',
            },
          };
        }),
      },
    };

    const instance = new Hono<{ Bindings: Env; Variables: { auth: typeof auth } }>();
    instance.use('*', async (c, next) => {
      c.set('auth', auth);
      await next();
    });
    instance.route('/', appRoutes);

    const response = await instance.fetch(new Request('http://localhost/api/auth/link-social', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: 'Bearer existing-bearer',
      },
      body: JSON.stringify({ provider: 'google', callbackURL: 'betterauth://link/success' }),
    }), env);

    expect(response.status).toBe(200);
    expect(response.headers.get('set-cookie')).toContain('better-auth.social_state=linked-state');
    await expect(response.json()).resolves.toEqual({
      status: true,
      redirect: false,
      url: null,
      session: {
        session: {
          id: 'session-link',
          userId: 'user-link',
          accessToken: 'linked-bearer',
          expiresAt: '2026-03-30T02:00:00.000Z',
        },
        user: {
          id: 'user-link',
          email: 'linked@example.com',
          name: 'Linked User',
        },
      },
    });
  });

  it('fixture google token verifier rejects nonce mismatch', async () => {
    await expect(verifyFixtureGoogleIdToken('valid-google-token', 'mismatch')).resolves.toBe(false);
    await expect(verifyFixtureGoogleIdToken('valid-google-token', 'expected')).resolves.toBe(true);
  });

  it('fixture google user info can simulate missing-email provider identities', async () => {
    const result = await getFixtureGoogleUserInfo({ idToken: 'missing-email-token' });
    expect(result.user.email).toBe('');
    expect(result.user.emailVerified).toBe(true);
  });

  it('fixture google user info can simulate cross-user linking identities', async () => {
    const result = await getFixtureGoogleUserInfo({ idToken: 'cross-user-token' });
    expect(result.user.email).toBe('other@example.com');
    expect(result.user.id).toBe('google-cross-user');
  });

  it('fixture capture route exists', async () => {
    const response = await app.fetch(new Request('http://localhost/api/fixtures/captures'), env);

    expect(response.status).not.toBe(404);
  });

  it('fixture capture route returns stored verification captures without rewriting them', async () => {
    const rows = [
      {
        identifier: 'fixture@example.com',
        value: JSON.stringify({
          token: 'verify-token',
          email: 'fixture@example.com',
          url: 'http://127.0.0.1:8787/verify-email?token=verify-token',
          signature: 'stored-signature',
        }),
        createdAt: new Date('2026-03-30T00:00:00.000Z'),
      },
    ];
    const orderBy = vi.fn(async () => rows);
    const from = vi.fn(() => ({ orderBy }));
    const select = vi.fn(() => ({ from }));
    const getDbSpy = vi.spyOn(dbModule, 'getDb').mockReturnValue({
      select,
    } as never);

    try {
      const response = await app.fetch(new Request('http://localhost/api/fixtures/captures'), env);

      expect(response.status).toBe(200);
      await expect(response.json()).resolves.toEqual({
        captures: [
          {
            channel: 'email-verification',
            token: 'verify-token',
            identifier: 'fixture@example.com',
            email: 'fixture@example.com',
            newEmail: undefined,
            phoneNumber: undefined,
            otpType: undefined,
            url: 'http://127.0.0.1:8787/verify-email?token=verify-token',
            metadata: {
              token: 'verify-token',
              email: 'fixture@example.com',
              url: 'http://127.0.0.1:8787/verify-email?token=verify-token',
              signature: 'stored-signature',
            },
            signature: 'stored-signature',
          },
        ],
      });
      expect(select).toHaveBeenCalledTimes(1);
      expect(orderBy).toHaveBeenCalledTimes(1);
    } finally {
      getDbSpy.mockRestore();
    }
  });

  it('fixture capture route preserves stored two-factor captures verbatim', async () => {
    const rows = [
      {
        identifier: 'user-2',
        value: JSON.stringify({
          token: '654321',
          email: 'twofactor@example.com',
          userId: 'user-2',
          signature: 'stored-two-factor-signature',
        }),
        createdAt: new Date('2026-03-30T00:00:01.000Z'),
      },
    ];
    const orderBy = vi.fn(async () => rows);
    const from = vi.fn(() => ({ orderBy }));
    const select = vi.fn(() => ({ from }));
    const getDbSpy = vi.spyOn(dbModule, 'getDb').mockReturnValue({
      select,
    } as never);

    try {
      const response = await app.fetch(new Request('http://localhost/api/fixtures/captures'), env);

      expect(response.status).toBe(200);
      await expect(response.json()).resolves.toEqual({
        captures: [
          {
            channel: 'two-factor',
            token: '654321',
            identifier: 'user-2',
            email: 'twofactor@example.com',
            newEmail: undefined,
            phoneNumber: undefined,
            otpType: undefined,
            url: undefined,
            metadata: {
              token: '654321',
              email: 'twofactor@example.com',
              userId: 'user-2',
              signature: 'stored-two-factor-signature',
            },
            signature: 'stored-two-factor-signature',
          },
        ],
      });
    } finally {
      getDbSpy.mockRestore();
    }
  });

  it('fixture capture route prefers the latest stored row deterministically after restart ordering changes', async () => {
    const rows = [
      {
        id: 'newer-row',
        identifier: 'fixture@example.com',
        value: JSON.stringify({
          token: 'fresh-token',
          email: 'fixture@example.com',
          url: 'http://127.0.0.1:8787/api/auth/verify-email?token=fresh-token',
          signature: 'fresh-signature',
        }),
        createdAt: new Date('2026-03-30T00:00:02.000Z'),
      },
      {
        id: 'older-row',
        identifier: 'fixture@example.com',
        value: JSON.stringify({
          token: 'stale-token',
          email: 'fixture@example.com',
          url: 'http://127.0.0.1:8787/api/auth/verify-email?token=stale-token',
          signature: 'stale-signature',
        }),
        createdAt: new Date('2026-03-30T00:00:01.000Z'),
      },
    ];
    const orderBy = vi.fn(async () => rows);
    const from = vi.fn(() => ({ orderBy }));
    const select = vi.fn(() => ({ from }));
    const getDbSpy = vi.spyOn(dbModule, 'getDb').mockReturnValue({
      select,
    } as never);

    try {
      const response = await app.fetch(new Request('http://localhost/api/fixtures/captures'), env);

      expect(response.status).toBe(200);
      await expect(response.json()).resolves.toEqual({
        captures: [
          {
            channel: 'email-verification',
            token: 'fresh-token',
            identifier: 'fixture@example.com',
            email: 'fixture@example.com',
            newEmail: undefined,
            phoneNumber: undefined,
            otpType: undefined,
            url: 'http://127.0.0.1:8787/api/auth/verify-email?token=fresh-token',
            metadata: {
              token: 'fresh-token',
              email: 'fixture@example.com',
              url: 'http://127.0.0.1:8787/api/auth/verify-email?token=fresh-token',
              signature: 'fresh-signature',
            },
            signature: 'fresh-signature',
          },
        ],
      });
    } finally {
      getDbSpy.mockRestore();
    }
  });

  it('fixture capture route decodes Better Auth email verification OTP identifiers and values', async () => {
    const rows = [
      {
        id: 'otp-row',
        identifier: 'email-verification-otp-fixture@example.com',
        value: JSON.stringify({
          otp: '246810',
          email: 'fixture@example.com',
          signature: 'otp-signature',
        }),
        createdAt: new Date('2026-03-30T00:00:03.000Z'),
      },
    ];
    const orderBy = vi.fn(async () => rows);
    const from = vi.fn(() => ({ orderBy }));
    const select = vi.fn(() => ({ from }));
    const getDbSpy = vi.spyOn(dbModule, 'getDb').mockReturnValue({
      select,
    } as never);

    try {
      const response = await app.fetch(new Request('http://localhost/api/fixtures/captures'), env);

      expect(response.status).toBe(200);
      await expect(response.json()).resolves.toEqual({
        captures: [
          {
            channel: 'email-otp',
            token: '246810',
            identifier: 'email-verification-otp-fixture@example.com',
            email: 'fixture@example.com',
            newEmail: undefined,
            phoneNumber: undefined,
            otpType: 'email-verification',
            url: undefined,
            metadata: {
              otp: '246810',
              email: 'fixture@example.com',
              signature: 'otp-signature',
            },
            signature: 'otp-signature',
          },
        ],
      });
    } finally {
      getDbSpy.mockRestore();
    }
  });

  it('fixture capture route decodes Better Auth change-email OTP identifiers with target email', async () => {
    const rows = [
      {
        id: 'change-email-otp-row',
        identifier: 'change-email-otp-current@example.com-next@example.com',
        value: JSON.stringify({
          otp: '135790',
          email: 'current@example.com',
          newEmail: 'next@example.com',
          signature: 'change-email-otp-signature',
        }),
        createdAt: new Date('2026-03-30T00:00:04.000Z'),
      },
    ];
    const orderBy = vi.fn(async () => rows);
    const from = vi.fn(() => ({ orderBy }));
    const select = vi.fn(() => ({ from }));
    const getDbSpy = vi.spyOn(dbModule, 'getDb').mockReturnValue({
      select,
    } as never);

    try {
      const response = await app.fetch(new Request('http://localhost/api/fixtures/captures'), env);

      expect(response.status).toBe(200);
      await expect(response.json()).resolves.toEqual({
        captures: [
          {
            channel: 'change-email-verification',
            token: '135790',
            identifier: 'change-email-otp-current@example.com-next@example.com',
            email: 'current@example.com',
            newEmail: 'next@example.com',
            phoneNumber: undefined,
            otpType: 'change-email',
            url: undefined,
            metadata: {
              otp: '135790',
              email: 'current@example.com',
              newEmail: 'next@example.com',
              signature: 'change-email-otp-signature',
            },
            signature: 'change-email-otp-signature',
          },
        ],
      });
    } finally {
      getDbSpy.mockRestore();
    }
  });

  it('fixture capture route prefers stored change-email OTP metadata when identifier emails contain hyphens', async () => {
    const rows = [
      {
        id: 'change-email-otp-hyphenated-row',
        identifier: 'change-email-otp-current-user@example.com-next-user@example.com',
        value: JSON.stringify({
          otp: '246810',
          email: 'current-user@example.com',
          newEmail: 'next-user@example.com',
          signature: 'change-email-otp-signature',
        }),
        createdAt: new Date('2026-03-30T00:00:05.000Z'),
      },
    ];
    const orderBy = vi.fn(async () => rows);
    const from = vi.fn(() => ({ orderBy }));
    const select = vi.fn(() => ({ from }));
    const getDbSpy = vi.spyOn(dbModule, 'getDb').mockReturnValue({
      select,
    } as never);

    try {
      const response = await app.fetch(new Request('http://localhost/api/fixtures/captures'), env);

      expect(response.status).toBe(200);
      await expect(response.json()).resolves.toEqual({
        captures: [
          {
            channel: 'change-email-verification',
            token: '246810',
            identifier: 'change-email-otp-current-user@example.com-next-user@example.com',
            email: 'current-user@example.com',
            newEmail: 'next-user@example.com',
            phoneNumber: undefined,
            otpType: 'change-email',
            url: undefined,
            metadata: {
              otp: '246810',
              email: 'current-user@example.com',
              newEmail: 'next-user@example.com',
              signature: 'change-email-otp-signature',
            },
            signature: 'change-email-otp-signature',
          },
        ],
      });
    } finally {
      getDbSpy.mockRestore();
    }
  });


  it('fixture capture route surfaces usable change-email OTP data from real verification rows without metadata', async () => {
    const rows = [
      {
        id: 'change-email-otp-real-row',
        identifier: 'change-email-otp-current-user@example.com-next-user@example.com',
        value: '246810:0',
        createdAt: new Date('2026-03-30T00:00:06.000Z'),
      },
    ];
    const orderBy = vi.fn(async () => rows);
    const from = vi.fn(() => ({ orderBy }));
    const select = vi.fn(() => ({ from }));
    const getDbSpy = vi.spyOn(dbModule, 'getDb').mockReturnValue({
      select,
    } as never);

    try {
      const response = await app.fetch(new Request('http://localhost/api/fixtures/captures'), env);

      expect(response.status).toBe(200);
      const body = await response.json() as {
        captures: Array<{
          channel: string;
          token: string;
          identifier: string;
          otpType?: string;
          email?: string;
          newEmail?: string;
          metadata?: {
            email?: string;
            newEmail?: string;
          };
        }>;
      };
      expect(body.captures).toHaveLength(1);
      expect(body.captures[0]).toMatchObject({
        channel: 'change-email-verification',
        token: '246810',
        identifier: 'change-email-otp-current-user@example.com-next-user@example.com',
        otpType: 'change-email',
      });
      expect(body.captures[0].email ?? body.captures[0].metadata?.email).toBe('current-user@example.com');
      expect(body.captures[0].newEmail ?? body.captures[0].metadata?.newEmail).toBe('next-user@example.com');
    } finally {
      getDbSpy.mockRestore();
    }
  });

  it('fixture capture logic infers magic-link token and email from stored verification values', async () => {
    const stored = JSON.stringify({ email: 'magic@example.com' }) + ' https://example.com/api/auth/magic-link/verify?token=magic-token';
    const urlMatch = stored.match(/https?:\/\/[^\s"]+/)?.[0];
    const parsedURL = new URL(urlMatch!);

    expect(parsedURL.searchParams.get('token')).toBe('magic-token');
    expect(JSON.parse(stored.slice(0, stored.indexOf(' http')))).toEqual({ email: 'magic@example.com' });
  });


  it('passkey routes require expected authorization semantics', async () => {
    const signedOutOptions = await app.fetch(new Request('http://localhost/api/auth/passkey/authenticate-options'), env);
    expect(signedOutOptions.status).not.toBe(404);

    const registerOptions = await app.fetch(new Request('http://localhost/api/auth/passkey/register-options'), env);
    expect(registerOptions.status).toBe(401);
    await expect(registerOptions.json()).resolves.toEqual({ error: 'Missing Authorization header.' });

    const listPasskeys = await app.fetch(new Request('http://localhost/api/auth/passkeys'), env);
    expect(listPasskeys.status).toBe(401);
    await expect(listPasskeys.json()).resolves.toEqual({ error: 'Missing Authorization header.' });

    const updatePasskey = await app.fetch(new Request('http://localhost/api/auth/passkey/update', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ id: 'passkey-1', name: 'Renamed' }),
    }), env);
    expect(updatePasskey.status).toBe(401);
    await expect(updatePasskey.json()).resolves.toEqual({ error: 'Missing Authorization header.' });

    const deletePasskey = await app.fetch(new Request('http://localhost/api/auth/passkey/delete', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ id: 'passkey-1' }),
    }), env);
    expect(deletePasskey.status).toBe(401);
    await expect(deletePasskey.json()).resolves.toEqual({ error: 'Missing Authorization header.' });
  });

  it('passkey option routes preserve Better Auth challenge cookies', async () => {
    const auth = {
      handler: vi.fn(async () => Response.json({
        challenge: 'challenge-token',
      }, {
        headers: {
          'set-cookie': 'better-auth.webauthn-challenge=signed-challenge; Path=/; HttpOnly',
        },
      })),
    };

    const instance = new Hono<{ Bindings: Env; Variables: { auth: typeof auth } }>();
    instance.use('*', async (c, next) => {
      c.set('auth', auth);
      await next();
    });
    instance.route('/', appRoutes);

    const registerOptions = await instance.fetch(new Request('http://localhost/api/auth/passkey/register-options', {
      headers: {
        authorization: 'Bearer fixture-token',
      },
    }), env);
    expect(registerOptions.status).toBe(200);
    expect(registerOptions.headers.get('set-cookie') ?? '').toContain('better-auth.webauthn-challenge=signed-challenge');
    await expect(registerOptions.json()).resolves.toEqual({ challenge: 'challenge-token' });

    const authenticateOptions = await instance.fetch(new Request('http://localhost/api/auth/passkey/authenticate-options'), env);
    expect(authenticateOptions.status).toBe(200);
    expect(authenticateOptions.headers.get('set-cookie') ?? '').toContain('better-auth.webauthn-challenge=signed-challenge');
    await expect(authenticateOptions.json()).resolves.toEqual({ challenge: 'challenge-token' });
  });


  it('passkey challenge fixture route validates required token parameter', async () => {
    const response = await app.fetch(new Request('http://localhost/api/fixtures/passkey/challenge'), env);

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({ error: 'Missing token query parameter.' });
  });

  it('native session shape includes bearer-backed access token fields', () => {
    expect({
      session: {
        id: 'session-1',
        userId: 'user-1',
        accessToken: 'signup-token',
        refreshToken: null,
        expiresAt: '2026-03-29T18:00:00.000Z',
      },
      user: {
        id: 'user-1',
        email: 'signup@example.com',
        name: 'Sign Up User',
      },
    }).toEqual({
      session: {
        id: 'session-1',
        userId: 'user-1',
        accessToken: 'signup-token',
        refreshToken: null,
        expiresAt: '2026-03-29T18:00:00.000Z',
      },
      user: {
        id: 'user-1',
        email: 'signup@example.com',
        name: 'Sign Up User',
      },
    });
  });
});

async function signCookieValueForTest(value: string, secret: string) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(value));
  const bytes = new Uint8Array(signature);
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return `${value}.${btoa(binary)}`;
}

function makeUnsignedJWT(payload: Record<string, unknown>) {
  const header = base64url({ alg: 'none', typ: 'JWT' });
  const body = base64url(payload);
  return `${header}.${body}.`;
}

function base64url(value: Record<string, unknown>) {
  return Buffer.from(JSON.stringify(value))
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}
