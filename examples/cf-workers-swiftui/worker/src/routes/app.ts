import { Hono } from 'hono';
import type { Context } from 'hono';
import type { AppAuth } from '../auth';
import { buildFixtureCapture, generateAppleClientSecret, getAppleAuthBaseURL } from '../auth';
import { getDb } from '../db';
import { profiles, schema } from '../db/schema';
import type { Env } from '../types';
import { and, desc, eq } from 'drizzle-orm';

export const appRoutes = new Hono<{ Bindings: Env; Variables: { auth: AppAuth } }>();

appRoutes.get('/', (c) => {
  return c.json({
    ok: true,
    message: 'Better Auth Swift example worker is running',
    authBasePath: '/api/auth',
    protectedRoute: '/api/me',
    appleNativeHint: 'POST /api/auth/apple/native with Apple native id token payload',
  });
});

appRoutes.get('/health', (c) => c.json({ ok: true }));

appRoutes.get('/api/fixtures/captures', async (c) => {
  const db = getDb(c.env);
  const rows = await db.select().from(schema.verification)
    .orderBy(desc(schema.verification.createdAt), desc(schema.verification.id));
  const latestByIdentifier = new Map<string, typeof rows[number]>();
  for (const row of rows) {
    if (!latestByIdentifier.has(row.identifier)) {
      latestByIdentifier.set(row.identifier, row);
    }
  }
  const captures = await Promise.all(Array.from(latestByIdentifier.values()).map(async (row) => {
    const url = extractURLFromValue(row.value);
    const metadata = extractJSONMetadata(row.value);
    const inferred = inferCapture(row.identifier, row.value);

    return {
      channel: inferred.channel,
      token: inferred.token,
      identifier: row.identifier,
      email: inferred.email,
      newEmail: inferred.newEmail,
      phoneNumber: inferred.phoneNumber,
      otpType: inferred.otpType,
      url,
      metadata,
      signature: extractCaptureSignature(metadata),
    };
  }));

  return c.json({
    captures,
  });
});

appRoutes.post('/api/auth/apple/native', async (c) => {
  const auth = c.get('auth');
  const payload = await c.req.json<{
    token: string;
    nonce?: string;
    authorizationCode?: string;
    email?: string;
    givenName?: string;
    familyName?: string;
  }>();

  const signInRequest = new Request(new URL('/api/auth/sign-in/social', c.env.BETTER_AUTH_URL), {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      origin: c.env.TRUSTED_ORIGIN,
    },
    body: JSON.stringify({
      provider: 'apple',
      disableRedirect: true,
      idToken: {
        token: payload.token,
        nonce: payload.nonce,
        user: {
          email: payload.email,
          name: {
            firstName: payload.givenName,
            lastName: payload.familyName,
          },
        },
      },
    }),
  });

  const signInResponse = await auth.handler(signInRequest);
  if (!signInResponse.ok) {
    return signInResponse;
  }

  const body = await signInResponse.json<{
    token?: string;
    user?: { id: string; email?: string; name?: string };
  }>();
  const accessToken = signInResponse.headers.get('set-auth-token') ?? body.token;
  if (!accessToken || !body.user) {
    return c.json({ error: 'Missing bearer token from Better Auth sign-in response.' }, 500);
  }

  if (payload.authorizationCode && (c.env.APPLE_AUTH_MODE ?? 'real') === 'real') {
    try {
      const clientSecret = await generateAppleClientSecret(c.env);
      if (clientSecret) {
        const tokenRes = await fetch(`${getAppleAuthBaseURL(c.env)}/auth/token`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            client_id: c.env.APPLE_CLIENT_ID,
            client_secret: clientSecret,
            code: payload.authorizationCode,
            grant_type: 'authorization_code',
          }),
        });
        if (tokenRes.ok) {
          const tokens = await tokenRes.json<{ refresh_token?: string; access_token?: string }>();
          if (tokens.refresh_token) {
            const db = getDb(c.env);
            await db.update(schema.account)
              .set({
                refreshToken: tokens.refresh_token,
                accessToken: tokens.access_token ?? null,
              })
              .where(and(eq(schema.account.userId, body.user.id), eq(schema.account.providerId, 'apple')));
          }
        } else {
          console.warn(`[auth] Apple token exchange failed: ${tokenRes.status} ${await tokenRes.text()}`);
        }
      }
    } catch (error) {
      console.warn(`[auth] Apple auth code exchange failed: ${String(error)}`);
    }
  }

  const session = await getSessionForBearer(c, auth, accessToken);

  if (!session?.session || !session.user) {
    return c.json({ error: 'Unable to load Better Auth session.' }, 500);
  }

  return c.json(session);
});

appRoutes.post('/api/auth/anonymous/sign-in', async (c) => {
  const auth = c.get('auth');
  const response = await callPublicAuthEndpoint(c, auth, '/api/auth/sign-in/anonymous', {
    method: 'POST',
  });

  if (!response.ok) {
    return mapAuthFailure(response);
  }

  const body = await response.json<{ token?: string; user?: BetterAuthSessionResponse['user'] }>();
  const accessToken = response.headers.get('set-auth-token') ?? body.token;
  if (!accessToken || !body.user) {
    return c.json({ error: 'Missing bearer token from Better Auth anonymous sign-in response.' }, 500);
  }

  return c.json({
    token: accessToken,
    user: body.user,
  });
});

appRoutes.post('/api/auth/anonymous/delete', async (c) => {
  const auth = c.get('auth');
  const accessToken = extractBearerToken(c.req.raw.headers);
  if (!accessToken) {
    return c.json({ error: 'Missing Authorization header.' }, 401);
  }

  if (!(await isActiveBearer(c, accessToken))) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  const response = await callAuthEndpoint(c, auth, '/api/auth/delete-anonymous-user', {
    method: 'POST',
    accessToken,
  });
  if (!response.ok) {
    return mapAuthFailure(response);
  }

  const revoked = await revokeBearerBackedSession(c, accessToken);
  if (!revoked) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  return c.json({ status: true });
});

appRoutes.post('/api/auth/oauth2/link', async (c) => {
  const auth = c.get('auth');
  const accessToken = extractBearerToken(c.req.raw.headers);
  if (!accessToken) {
    return c.json({ error: 'Missing Authorization header.' }, 401);
  }

  const payload = await c.req.json<Record<string, unknown>>();
  const response = await callAuthEndpoint(c, auth, '/api/auth/oauth2/link', {
    method: 'POST',
    accessToken,
    body: payload,
  });

  const responseCookies = copySetCookies(response.headers);
  if (!response.ok && !isSuccessfulOAuthRedirect(response)) {
    return mapAuthFailureWithHeaders(response, responseCookies);
  }

  const body = await response.json<{ url: string; redirect: boolean }>();
  return Response.json(body, {
    headers: appendSetCookies(new Headers(), responseCookies),
  });
});

appRoutes.post('/api/auth/email/sign-up', async (c) => {
  const auth = c.get('auth');
  const payload = await c.req.json<{
    email: string;
    password: string;
    name: string;
  }>();

  return handleEmailAuth(c, auth, '/api/auth/sign-up/email', payload);
});

appRoutes.post('/api/auth/email/sign-in', async (c) => {
  const auth = c.get('auth');
  const payload = await c.req.json<{
    email: string;
    password: string;
  }>();

  return handleEmailAuth(c, auth, '/api/auth/sign-in/email', payload, {
    propagateTwoFactorChallengeCookie: true,
  });
});

appRoutes.post('/api/auth/username/sign-in', async (c) => {
  const auth = c.get('auth');
  const payload = await c.req.json<{
    username: string;
    password: string;
  }>();

  const authRequest = new Request(new URL('/api/auth/sign-in/username', c.env.BETTER_AUTH_URL), {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      origin: c.env.TRUSTED_ORIGIN,
    },
    body: JSON.stringify(payload),
  });

  const authResponse = await auth.handler(authRequest);
  const twoFactorCookie = copySetCookie(authResponse.headers, 'better-auth.two_factor');
  const dontRememberCookie = copySetCookie(authResponse.headers, 'better-auth.dont_remember');
  if (twoFactorCookie || dontRememberCookie) {
    return mapAuthFailureWithHeaders(
      authResponse,
      [twoFactorCookie, dontRememberCookie].filter((value): value is string => Boolean(value)),
    );
  }

  const mappedError = await mapUsernameSignInFailure(authResponse);
  if (mappedError) {
    return mappedError;
  }

  const accessToken = authResponse.headers.get('set-auth-token');
  if (!accessToken) {
    return c.json({ error: 'Missing bearer token from Better Auth auth response.' }, 500);
  }

  const session = await getSessionForBearer(c, auth, accessToken);

  if (!session?.session || !session.user) {
    return c.json({ error: 'Unable to load Better Auth session.' }, 500);
  }

  return c.json(session);
});

appRoutes.post('/api/auth/magic-link/sign-in', async (c) => {
  const auth = c.get('auth');
  const payload = await c.req.json<{
    email: string;
    name?: string;
    callbackURL?: string;
    newUserCallbackURL?: string;
    errorCallbackURL?: string;
    metadata?: Record<string, unknown>;
  }>();

  const response = await callPublicAuthEndpoint(c, auth, '/api/auth/sign-in/magic-link', {
    method: 'POST',
    body: payload,
  });

  if (!response.ok) {
    return mapAuthFailure(response);
  }

  return c.json(await response.json<BetterAuthStatusResponse>());
});

appRoutes.post('/api/auth/email-otp/verify', async (c) => {
  const auth = c.get('auth');
  const payload = await c.req.json<{
    email: string;
    otp: string;
  }>();

  const response = await callPublicAuthEndpoint(c, auth, '/api/auth/email-otp/verify-email', {
    method: 'POST',
    body: payload,
  });

  if (!response.ok) {
    return mapAuthFailure(response);
  }

  const body = await response.json<{ status: boolean; token?: string | null; user: BetterAuthSessionResponse['user'] }>();
  const accessToken = response.headers.get('set-auth-token') ?? body.token;
  if (accessToken) {
    const session = await getSessionForBearer(c, auth, accessToken);

    if (!session?.session || !session.user) {
      return c.json({ error: 'Unable to load Better Auth session.' }, 500);
    }

    return c.json({
      status: true,
      session,
      user: {
        id: session.user.id,
        email: session.user.email,
        name: session.user.name,
        username: session.user.username,
        displayUsername: session.user.displayUsername,
      },
    });
  }

  return c.json({
    status: body.status,
    session: null,
    user: {
      id: body.user.id,
      email: body.user.email,
      name: body.user.name,
      username: body.user.username,
      displayUsername: body.user.displayUsername,
    },
  });
});

appRoutes.post('/api/auth/phone-number/verify', async (c) => {
  const auth = c.get('auth');
  const payload = await c.req.json<{
    phoneNumber: string;
    code: string;
    disableSession?: boolean;
    updatePhoneNumber?: boolean;
  }>();
  let response: Response;

  if (payload.updatePhoneNumber) {
    const accessToken = extractBearerToken(c.req.raw.headers);
    if (!accessToken) {
      return c.json({ error: 'Missing Authorization header.' }, 401);
    }

    if (!(await isActiveBearer(c, accessToken))) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    response = await callAuthEndpoint(c, auth, '/api/auth/phone-number/verify', {
      method: 'POST',
      accessToken,
      body: payload,
    });
  } else {
    response = await callPublicAuthEndpoint(c, auth, '/api/auth/phone-number/verify', {
      method: 'POST',
      body: payload,
    });
  }

  if (!response.ok) {
    return mapAuthFailure(response);
  }

  return c.json(await response.json<{
    status: boolean;
    token?: string | null;
    user?: BetterAuthSessionResponse['user'] | null;
  }>());
});

appRoutes.post('/api/auth/phone-number/sign-in', async (c) => {
  const auth = c.get('auth');
  const payload = await c.req.json<{
    phoneNumber: string;
    password: string;
    rememberMe?: boolean;
  }>();

  const response = await callPublicAuthEndpoint(c, auth, '/api/auth/sign-in/phone-number', {
    method: 'POST',
    body: payload,
  });

  if (!response.ok) {
    return mapAuthFailure(response);
  }

  const body = await response.json<TwoFactorSessionResponse>();
  const accessToken = response.headers.get('set-auth-token') ?? body.token;
  if (!accessToken) {
    return c.json({ error: 'Missing bearer token from Better Auth phone-number sign-in response.' }, 500);
  }

  return c.json({
    token: accessToken,
    user: {
      id: body.user.id,
      email: body.user.email,
      name: body.user.name,
      username: body.user.username,
      displayUsername: body.user.displayUsername,
      twoFactorEnabled: body.user.twoFactorEnabled ?? false,
    },
  });
});

appRoutes.post('/api/auth/two-factor/enable', async (c) => {
  const auth = c.get('auth');
  const accessToken = extractBearerToken(c.req.raw.headers);
  if (!accessToken) {
    return c.json({ error: 'Missing Authorization header.' }, 401);
  }

  if (!(await isActiveBearer(c, accessToken))) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  const payload = await c.req.json<{
    password: string;
    issuer?: string;
  }>();

  const response = await callAuthEndpoint(c, auth, '/api/auth/two-factor/enable', {
    method: 'POST',
    accessToken,
    body: payload,
  });

  if (!response.ok) {
    return mapAuthFailure(response);
  }

  return c.json(await response.json<TwoFactorEnableResponse>());
});

appRoutes.post('/api/auth/two-factor/verify-totp', async (c) => {
  const auth = c.get('auth');
  const payload = await c.req.json<{
    code: string;
    trustDevice?: boolean;
  }>();
  const accessToken = extractBearerToken(c.req.raw.headers);
  const cookie = accessToken ? null : await resolveTwoFactorCookie(c, auth);

  const response = accessToken
    ? await callAuthEndpoint(c, auth, '/api/auth/two-factor/verify-totp', {
        method: 'POST',
        accessToken,
        body: payload,
      })
    : await callPublicAuthEndpoint(c, auth, '/api/auth/two-factor/verify-totp', {
        method: 'POST',
        body: payload,
        cookie,
      });

  return mapTwoFactorChallengeResponse(c, auth, response);
});

appRoutes.post('/api/auth/two-factor/send-otp', async (c) => {
  const auth = c.get('auth');
  const payload = await c.req.json<{
    trustDevice?: boolean;
  }>();
  const cookie = await resolveTwoFactorCookie(c, auth);

  const response = await callPublicAuthEndpoint(c, auth, '/api/auth/two-factor/send-otp', {
    method: 'POST',
    body: payload,
    cookie,
  });

  if (!response.ok) {
    return mapAuthFailure(response);
  }

  return c.json(await response.json<BetterAuthStatusResponse>());
});

appRoutes.post('/api/auth/two-factor/verify-otp', async (c) => {
  const auth = c.get('auth');
  const payload = await c.req.json<{
    code: string;
    trustDevice?: boolean;
  }>();
  const cookie = await resolveTwoFactorCookie(c, auth);

  const response = await callPublicAuthEndpoint(c, auth, '/api/auth/two-factor/verify-otp', {
    method: 'POST',
    body: payload,
    cookie,
  });

  return mapTwoFactorChallengeResponse(c, auth, response);
});

appRoutes.post('/api/auth/two-factor/verify-backup-code', async (c) => {
  const auth = c.get('auth');
  const payload = await c.req.json<{
    code: string;
    trustDevice?: boolean;
    disableSession?: boolean;
  }>();
  const cookie = await resolveTwoFactorCookie(c, auth);

  const response = await callPublicAuthEndpoint(c, auth, '/api/auth/two-factor/verify-backup-code', {
    method: 'POST',
    body: payload,
    cookie,
  });

  return mapTwoFactorChallengeResponse(c, auth, response);
});

appRoutes.post('/api/auth/two-factor/generate-backup-codes', async (c) => {
  const auth = c.get('auth');
  const accessToken = extractBearerToken(c.req.raw.headers);
  if (!accessToken) {
    return c.json({ error: 'Missing Authorization header.' }, 401);
  }

  if (!(await isActiveBearer(c, accessToken))) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  const payload = await c.req.json<{ password: string }>();
  const response = await callAuthEndpoint(c, auth, '/api/auth/two-factor/generate-backup-codes', {
    method: 'POST',
    accessToken,
    body: payload,
  });

  if (!response.ok) {
    return mapAuthFailure(response);
  }

  return c.json(await response.json<TwoFactorGenerateBackupCodesResponse>());
});

appRoutes.post('/api/auth/update-user', async (c) => {
  const auth = c.get('auth');
  const accessToken = extractBearerToken(c.req.raw.headers);
  if (!accessToken) {
    return c.json({ error: 'Missing Authorization header.' }, 401);
  }

  if (!(await isActiveBearer(c, accessToken))) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  const payload = await c.req.json<Record<string, unknown>>();
  const response = await callAuthEndpoint(c, auth, '/api/auth/update-user', {
    method: 'POST',
    accessToken,
    body: payload,
  });

  if (!response.ok) {
    return mapAuthFailure(response);
  }

  const result = await response.json<{ status: boolean }>();
  const session = await getSessionForBearer(c, auth, accessToken);

  return c.json({
    status: result.status,
    user: session?.user
      ? {
          id: session.user.id,
          email: session.user.email,
          name: session.user.name,
          username: session.user.username,
          displayUsername: session.user.displayUsername,
        }
      : null,
  });
});

appRoutes.post('/api/auth/forget-password/email', async (c) => {
  const auth = c.get('auth');
  const payload = await c.req.json<{
    email: string;
    redirectTo?: string;
  }>();

  const response = await callPublicAuthEndpoint(c, auth, '/api/auth/request-password-reset', {
    method: 'POST',
    body: payload,
  });

  if (!response.ok) {
    return mapAuthFailure(response);
  }

  return c.json(await response.json<BetterAuthStatusResponse>());
});

appRoutes.post('/api/auth/reset-password', async (c) => {
  const auth = c.get('auth');
  const payload = await c.req.json<{
    token: string;
    newPassword: string;
  }>();

  const response = await callPublicAuthEndpoint(c, auth, '/api/auth/reset-password', {
    method: 'POST',
    body: payload,
  });

  if (!response.ok) {
    return mapAuthFailure(response);
  }

  return c.json(await response.json<BetterAuthStatusResponse>());
});

appRoutes.post('/api/auth/send-verification-email', async (c) => {
  const auth = c.get('auth');
  const accessToken = extractBearerToken(c.req.raw.headers);
  if (!accessToken) {
    return c.json({ error: 'Missing Authorization header.' }, 401);
  }

  if (!(await isActiveBearer(c, accessToken))) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  const payload = await c.req.json<{
    email?: string;
    callbackURL?: string;
  }>();
  const response = await callAuthEndpoint(c, auth, '/api/auth/send-verification-email', {
    method: 'POST',
    accessToken,
    body: payload,
  });

  if (!response.ok) {
    return mapAuthFailure(response);
  }

  return c.json(await response.json<BetterAuthStatusResponse>());
});

appRoutes.post('/api/auth/change-email', async (c) => {
  const auth = c.get('auth');
  const accessToken = extractBearerToken(c.req.raw.headers);
  if (!accessToken) {
    return c.json({ error: 'Missing Authorization header.' }, 401);
  }

  if (!(await isActiveBearer(c, accessToken))) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  const payload = await c.req.json<{
    newEmail: string;
    callbackURL?: string;
  }>();

  const response = await callAuthEndpoint(c, auth, '/api/auth/change-email', {
    method: 'POST',
    accessToken,
    body: payload,
  });

  if (!response.ok) {
    return mapAuthFailure(response);
  }

  return c.json(await response.json<BetterAuthStatusResponse>());
});

appRoutes.post('/api/auth/change-password', async (c) => {
  const auth = c.get('auth');
  const accessToken = extractBearerToken(c.req.raw.headers);
  if (!accessToken) {
    return c.json({ error: 'Missing Authorization header.' }, 401);
  }

  if (!(await isActiveBearer(c, accessToken))) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  const payload = await c.req.json<{
    currentPassword: string;
    newPassword: string;
    revokeOtherSessions?: boolean;
  }>();

  const response = await callAuthEndpoint(c, auth, '/api/auth/change-password', {
    method: 'POST',
    accessToken,
    body: payload,
  });

  if (!response.ok) {
    return mapAuthFailure(response);
  }

  const result = await response.json<{ token: string | null; user: BetterAuthSessionResponse['user'] }>();
  const refreshedToken = response.headers.get('set-auth-token') ?? result.token;
  let refreshedSession: BetterAuthSessionResponse | null = null;
  let user = result.user;
  if (refreshedToken) {
    refreshedSession = await auth.api.getSession({
      headers: new Headers({
        Authorization: `Bearer ${refreshedToken}`,
      }),
    }) as BetterAuthSessionResponse | null;
    if (refreshedSession?.user) {
      user = refreshedSession.user;
    }
  }
  return c.json({
    token: refreshedToken,
    session: refreshedSession,
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      username: user.username,
      displayUsername: user.displayUsername,
    },
  });
});

appRoutes.get('/api/auth/list-sessions', async (c) => {
  const auth = c.get('auth');
  const accessToken = extractBearerToken(c.req.raw.headers);
  if (!accessToken) {
    return c.json({ error: 'Missing Authorization header.' }, 401);
  }

  if (!(await isActiveBearer(c, accessToken))) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  const response = await callAuthEndpoint(c, auth, '/api/auth/list-sessions', {
    method: 'GET',
    accessToken,
  });
  if (!response.ok) {
    return mapAuthFailure(response);
  }

  const sessions = await response.json<BetterAuthSessionInventoryItem[]>();
  return c.json(sessions.filter((session) => isSessionActive(session.expiresAt)));
});

appRoutes.get('/api/auth/device-sessions', async (c) => {
  const auth = c.get('auth');
  const accessToken = extractBearerToken(c.req.raw.headers);
  if (!accessToken) {
    return c.json({ error: 'Missing Authorization header.' }, 401);
  }

  if (!(await isActiveBearer(c, accessToken))) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  const multiSessionCookie = await resolveMultiSessionCookies(c, auth, accessToken);
  if (!multiSessionCookie) {
    return c.json([], 200);
  }

  const response = await callAuthEndpoint(c, auth, '/api/auth/multi-session/list-device-sessions', {
    method: 'GET',
    accessToken,
    cookie: multiSessionCookie,
  });
  if (!response.ok) {
    return mapAuthFailure(response);
  }

  const sessions = await response.json<BetterAuthDeviceSessionItem[]>();
  return c.json(sessions.filter((item) => isSessionActive(item.session.expiresAt)));
});

appRoutes.post('/api/auth/device-sessions/set-active', async (c) => {
  const auth = c.get('auth');
  const accessToken = extractBearerToken(c.req.raw.headers);
  if (!accessToken) {
    return c.json({ error: 'Missing Authorization header.' }, 401);
  }

  if (!(await isActiveBearer(c, accessToken))) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  const payload = await c.req.json<{ sessionToken: string }>();
  const multiSessionCookie = await resolveMultiSessionCookies(c, auth, accessToken, payload.sessionToken);
  if (!multiSessionCookie) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  const response = await callAuthEndpoint(c, auth, '/api/auth/multi-session/set-active', {
    method: 'POST',
    accessToken,
    body: payload,
    cookie: multiSessionCookie,
  });
  if (!response.ok) {
    return mapAuthFailure(response);
  }

  const body = await response.json<BetterAuthSessionResponse>();
  return c.json({
    session: {
      ...body.session,
      accessToken: payload.sessionToken,
    },
    user: body.user,
  });
});

appRoutes.post('/api/auth/device-sessions/revoke', async (c) => {
  const auth = c.get('auth');
  const accessToken = extractBearerToken(c.req.raw.headers);
  if (!accessToken) {
    return c.json({ error: 'Missing Authorization header.' }, 401);
  }

  if (!(await isActiveBearer(c, accessToken))) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  const payload = await c.req.json<{ sessionToken: string }>();
  const multiSessionCookie = await resolveMultiSessionCookies(c, auth, accessToken, payload.sessionToken);
  if (!multiSessionCookie) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  const response = await callAuthEndpoint(c, auth, '/api/auth/multi-session/revoke', {
    method: 'POST',
    accessToken,
    body: payload,
    cookie: multiSessionCookie,
  });
  if (!response.ok) {
    return mapAuthFailure(response);
  }

  return c.json(await response.json<{ status: boolean }>());
});

appRoutes.get('/api/auth/jwks', async (c) => {
  const auth = c.get('auth');
  const response = await callPublicAuthEndpoint(c, auth, '/api/auth/jwks', {
    method: 'GET',
  });
  if (!response.ok) {
    return mapAuthFailure(response);
  }

  return c.json(await response.json<BetterAuthJWKSResponse>());
});

appRoutes.get('/api/auth/list-accounts', async (c) => {
  const auth = c.get('auth');
  const accessToken = extractBearerToken(c.req.raw.headers);
  if (!accessToken) {
    return c.json({ error: 'Missing Authorization header.' }, 401);
  }

  if (!(await isActiveBearer(c, accessToken))) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  const response = await callAuthEndpoint(c, auth, '/api/auth/list-accounts', {
    method: 'GET',
    accessToken,
  });
  if (!response.ok) {
    return mapAuthFailure(response);
  }

  return new Response(await response.text(), {
    status: response.status,
    headers: response.headers,
  });
});

appRoutes.post('/api/auth/link-social', async (c) => {
  const auth = c.get('auth');
  const accessToken = extractBearerToken(c.req.raw.headers);
  if (!accessToken) {
    return c.json({ error: 'Missing Authorization header.' }, 401);
  }

  const payload = await c.req.json<Record<string, unknown>>();
  const response = await callAuthEndpoint(c, auth, '/api/auth/link-social', {
    method: 'POST',
    accessToken,
    body: payload,
  });
  const responseCookies = copySetCookies(response.headers);
  if (!response.ok && !isSuccessfulOAuthRedirect(response)) {
    return mapAuthFailureWithHeaders(response, responseCookies);
  }

  const accessTokenFromHeaders = response.headers.get('set-auth-token');
  if (accessTokenFromHeaders) {
    const session = await auth.api.getSession({
      headers: new Headers({
        Authorization: `Bearer ${accessTokenFromHeaders}`,
      }),
    }) as BetterAuthSessionResponse | null;

    if (!session?.session || !session.user) {
      return c.json({ error: 'Unable to load Better Auth session.' }, 500);
    }

    return Response.json({
      status: true,
      redirect: false,
      url: null,
      session: {
        session: {
          ...session.session,
          accessToken: accessTokenFromHeaders,
        },
        user: session.user,
      },
    }, {
      headers: appendSetCookies(new Headers(), responseCookies),
    });
  }

  const body = await response.json();
  return Response.json(body, {
    headers: appendSetCookies(new Headers(), responseCookies),
  });
});

appRoutes.post('/api/auth/revoke-session', async (c) => {
  const auth = c.get('auth');
  const accessToken = extractBearerToken(c.req.raw.headers);
  if (!accessToken) {
    return c.json({ error: 'Missing Authorization header.' }, 401);
  }

  if (!(await isActiveBearer(c, accessToken))) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  const payload = await c.req.json<{ token: string }>();
  const response = await callAuthEndpoint(c, auth, '/api/auth/revoke-session', {
    method: 'POST',
    accessToken,
    body: payload,
  });

  if (!response.ok) {
    return mapAuthFailure(response);
  }

  return c.json(await response.json<{ status: boolean }>());
});

appRoutes.post('/api/auth/revoke-sessions', async (c) => {
  const auth = c.get('auth');
  const accessToken = extractBearerToken(c.req.raw.headers);
  if (!accessToken) {
    return c.json({ error: 'Missing Authorization header.' }, 401);
  }

  if (!(await isActiveBearer(c, accessToken))) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  const response = await callAuthEndpoint(c, auth, '/api/auth/revoke-sessions', {
    method: 'POST',
    accessToken,
  });
  if (!response.ok) {
    return mapAuthFailure(response);
  }

  return c.json(await response.json<{ status: boolean }>());
});

appRoutes.post('/api/auth/revoke-other-sessions', async (c) => {
  const auth = c.get('auth');
  const accessToken = extractBearerToken(c.req.raw.headers);
  if (!accessToken) {
    return c.json({ error: 'Missing Authorization header.' }, 401);
  }

  if (!(await isActiveBearer(c, accessToken))) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  const response = await callAuthEndpoint(c, auth, '/api/auth/revoke-other-sessions', {
    method: 'POST',
    accessToken,
  });
  if (!response.ok) {
    return mapAuthFailure(response);
  }

  return c.json(await response.json<{ status: boolean }>());
});

appRoutes.post('/api/auth/sign-out', async (c) => {
  const auth = c.get('auth');
  const accessToken = extractBearerToken(c.req.raw.headers);
  if (!accessToken) {
    return c.json({ error: 'Missing Authorization header.' }, 401);
  }

  if (!(await isActiveBearer(c, accessToken))) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  const response = await callAuthEndpoint(c, auth, '/api/auth/sign-out', {
    method: 'POST',
    accessToken,
  });
  if (!response.ok) {
    return mapAuthFailure(response);
  }

  const revoked = await revokeBearerBackedSession(c, accessToken);
  if (!revoked) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  return c.json({ success: true });
});

appRoutes.get('/api/auth/passkey/register-options', async (c) => {
  const auth = c.get('auth');
  const accessToken = extractBearerToken(c.req.raw.headers);
  if (!accessToken) {
    return c.json({ error: 'Missing Authorization header.' }, 401);
  }

  if (!(await isActiveBearer(c, accessToken))) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  const params = new URL(c.req.url).searchParams;
  const query = new URLSearchParams();
  if (params.get('name')) {
    query.set('name', params.get('name')!);
  }
  if (params.get('authenticatorAttachment')) {
    query.set('authenticatorAttachment', params.get('authenticatorAttachment')!);
  }

  const path = query.size > 0
    ? `/api/auth/passkey/generate-register-options?${query.toString()}`
    : '/api/auth/passkey/generate-register-options';
  const response = await callAuthEndpoint(c, auth, path, {
    method: 'GET',
    accessToken,
    setCookieNames: ['better-auth.webauthn-challenge'],
  });
  if (!response.ok) {
    return mapAuthFailure(response);
  }

  return new Response(await response.text(), {
    status: response.status,
    headers: response.headers,
  });
});

appRoutes.get('/api/auth/passkey/authenticate-options', async (c) => {
  const auth = c.get('auth');
  const accessToken = extractBearerToken(c.req.raw.headers);
  const response = accessToken
    ? await callAuthEndpoint(c, auth, '/api/auth/passkey/generate-authenticate-options', {
        method: 'GET',
        accessToken,
        setCookieNames: ['better-auth.webauthn-challenge'],
      })
    : await callPublicAuthEndpoint(c, auth, '/api/auth/passkey/generate-authenticate-options', {
        method: 'GET',
        setCookieNames: ['better-auth.webauthn-challenge'],
      });

  if (!response.ok) {
    return mapAuthFailure(response);
  }

  return new Response(await response.text(), {
    status: response.status,
    headers: response.headers,
  });
});

appRoutes.post('/api/auth/passkey/register', async (c) => {
  const auth = c.get('auth');
  const accessToken = extractBearerToken(c.req.raw.headers);
  if (!accessToken) {
    return c.json({ error: 'Missing Authorization header.' }, 401);
  }

  if (!(await isActiveBearer(c, accessToken))) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  const payload = await c.req.json<Record<string, unknown>>();
  const response = await callAuthEndpoint(c, auth, '/api/auth/passkey/verify-registration', {
    method: 'POST',
    accessToken,
    body: payload,
    cookie: resolveCookieHeader(c.req.raw.headers, ['better-auth.webauthn-challenge']),
  });

  if (!response.ok) {
    return mapAuthFailure(response);
  }

  return c.json(formatPasskey(await response.json<BetterAuthPasskey>()));
});

appRoutes.get('/api/auth/passkeys', async (c) => {
  const auth = c.get('auth');
  const accessToken = extractBearerToken(c.req.raw.headers);
  if (!accessToken) {
    return c.json({ error: 'Missing Authorization header.' }, 401);
  }

  if (!(await isActiveBearer(c, accessToken))) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  const response = await callAuthEndpoint(c, auth, '/api/auth/passkey/list-user-passkeys', {
    method: 'GET',
    accessToken,
  });
  if (!response.ok) {
    return mapAuthFailure(response);
  }

  const passkeys = await response.json<BetterAuthPasskey[]>();
  return c.json(passkeys.map(formatPasskey));
});

appRoutes.post('/api/auth/passkey/update', async (c) => {
  const auth = c.get('auth');
  const accessToken = extractBearerToken(c.req.raw.headers);
  if (!accessToken) {
    return c.json({ error: 'Missing Authorization header.' }, 401);
  }

  if (!(await isActiveBearer(c, accessToken))) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  const payload = await c.req.json<Record<string, unknown>>();
  const response = await callAuthEndpoint(c, auth, '/api/auth/passkey/update-passkey', {
    method: 'POST',
    accessToken,
    body: payload,
  });
  if (!response.ok) {
    return mapAuthFailure(response);
  }

  const body = await response.json<{ passkey: BetterAuthPasskey }>();
  return c.json({ passkey: formatPasskey(body.passkey) });
});

appRoutes.post('/api/auth/passkey/delete', async (c) => {
  const auth = c.get('auth');
  const accessToken = extractBearerToken(c.req.raw.headers);
  if (!accessToken) {
    return c.json({ error: 'Missing Authorization header.' }, 401);
  }

  if (!(await isActiveBearer(c, accessToken))) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  const payload = await c.req.json<Record<string, unknown>>();
  const response = await callAuthEndpoint(c, auth, '/api/auth/passkey/delete-passkey', {
    method: 'POST',
    accessToken,
    body: payload,
  });
  if (!response.ok) {
    return mapAuthFailure(response);
  }

  return c.json(await response.json<BetterAuthStatusResponse>());
});

appRoutes.get('/api/fixtures/passkey/challenge', async (c) => {
  const token = new URL(c.req.url).searchParams.get('token');
  if (!token) {
    return c.json({ error: 'Missing token query parameter.' }, 400);
  }

  const db = getDb(c.env);
  const row = await db.query.verification.findFirst({
    where: eq(schema.verification.identifier, token),
    columns: {
      identifier: true,
      value: true,
      expiresAt: true,
    },
  });

  if (!row) {
    return c.json({ error: 'Challenge not found.' }, 404);
  }

  try {
    const parsed = JSON.parse(row.value) as PasskeyChallengeFixture;
    return c.json({
      token: row.identifier,
      challenge: parsed.challenge ?? parsed.expectedChallenge,
      expiresAt: row.expiresAt,
      origin: parsed.origin,
      rpId: parsed.rpId,
      userId: parsed.userId,
      kind: parsed.kind,
    });
  } catch {
    return c.json({ error: 'Stored challenge is not valid JSON.' }, 500);
  }
});

appRoutes.get('/api/me', async (c) => {
  const auth = c.get('auth');
  const accessToken = extractBearerToken(c.req.raw.headers);
  if (!accessToken || !(await isActiveBearer(c, accessToken))) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  const session = await getSessionForBearer(c, auth, accessToken);

  if (!session?.user) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  const db = getDb(c.env);
  await db.insert(profiles).values({
    id: session.user.id,
    email: session.user.email ?? '',
    createdAt: new Date(),
  }).onConflictDoNothing();

  return c.json({
    user: session.user,
    session: session.session,
  });
});

type BetterAuthStatusResponse = {
  status: boolean;
};

type TwoFactorEnableResponse = {
  totpURI: string;
  backupCodes: string[];
};

type TwoFactorGenerateBackupCodesResponse = {
  status: boolean;
  backupCodes: string[];
};

type TwoFactorSessionResponse = {
  token: string;
  session?: BetterAuthSessionResponse['session'] | null;
  user: BetterAuthSessionResponse['user'] & {
    twoFactorEnabled?: boolean | null;
  };
};

type AuthEndpointOptions = {
  method: 'GET' | 'POST';
  body?: unknown;
  cookie?: string | null;
  setCookieNames?: string[];
};

type EmailOTPRequestResponse = {
  success: boolean;
};

type PhoneOTPRequestResponse = {
  message: string;
};

type BetterAuthPasskey = {
  id: string;
  name?: string | null;
  publicKey: string;
  userId: string;
  credentialID: string;
  counter: number;
  deviceType: string;
  backedUp: boolean;
  transports?: string | null;
  createdAt?: string | Date | null;
  aaguid?: string | null;
};

type PasskeyChallengeFixture = {
  challenge?: string;
  expectedChallenge?: string;
  rpId?: string;
  origin?: string;
  userId?: string;
  kind?: 'registration' | 'authentication';
};

type BetterAuthSessionResponse = {
  session: {
    id: string;
    userId: string;
    expiresAt: string | Date | null;
  };
  user: {
    id: string;
    email?: string | null;
    name?: string | null;
    username?: string | null;
    displayUsername?: string | null;
  };
};

type CaptureJSON = {
  email?: string;
  newEmail?: string;
  otp?: string;
  token?: string;
  code?: string;
  runtimeMode?: string;
  signature?: string;
  userId?: string;
  url?: string;
  user?: {
    email?: string;
  };
};

type BetterAuthEmailSignUpResponse = BetterAuthSessionResponse | {
  token: string | null;
  user: BetterAuthSessionResponse['user'];
};


export async function mapEmailSignInFailure(response: Response) {
  const mappedError = await mapEmailAuthContractFailure(response);
  if (mappedError) {
    return mappedError;
  }

  if (!response.ok) {
    return response;
  }

  return null;
}

export async function mapUsernameSignInFailure(response: Response) {
  if (!response.ok) {
    return mapAuthFailure(response);
  }

  return null;
}

export async function mapEmailAuthResponse(
  c: Context<{ Bindings: Env; Variables: { auth: AppAuth } }>,
  authResponse: Response,
  auth: AppAuth,
) {
  if (!authResponse.ok) {
    const mappedError = await mapEmailAuthContractFailure(authResponse);
    if (mappedError) {
      return mappedError;
    }
    return authResponse;
  }

  const body = await authResponse.clone().json<BetterAuthEmailSignUpResponse>();
  if (!('session' in body) && body.token === null) {
    const configuredRequireEmailVerification = (
      auth.options.emailAndPassword as { requireEmailVerification?: boolean } | undefined
    )?.requireEmailVerification;
    return c.json({
      requiresVerification: configuredRequireEmailVerification ?? false,
      user: {
        id: body.user.id,
        email: body.user.email,
        name: body.user.name,
        username: body.user.username,
        displayUsername: body.user.displayUsername,
      },
    });
  }

  const accessToken = authResponse.headers.get('set-auth-token');
  if (!accessToken) {
    return c.json({ error: 'Missing bearer token from Better Auth auth response.' }, 500);
  }

  const session = await getSessionForBearer(c, auth, accessToken);

  if (!session?.session || !session.user) {
    return c.json({ error: 'Unable to load Better Auth session.' }, 500);
  }

  return c.json(session);
}


async function isActiveBearer(c: Context<{ Bindings: Env; Variables: { auth: AppAuth } }>, accessToken: string) {
  const auth = c.get('auth');
  if (!auth.api?.getSession) {
    return true;
  }
  const session = await getSessionForBearer(c, auth, accessToken);

  if (!session?.session || !session.user) {
    return false;
  }

  return isSessionActive(session.session.expiresAt);
}

async function getSessionForBearer(
  c: Context<{ Bindings: Env; Variables: { auth: AppAuth } }>,
  auth: AppAuth,
  accessToken: string,
) {
  const directSession = await loadSessionViaBearer(auth, accessToken);
  if (directSession?.session && directSession.user) {
    return directSession;
  }

  const cookie = await resolveProtectedAuthCookie(c, auth, accessToken);
  if (!cookie) {
    return null;
  }

  const response = await callPublicAuthEndpoint(c, auth, '/api/auth/get-session', {
    method: 'GET',
    cookie,
  });

  if (!response.ok) {
    return null;
  }

  return await response.json<BetterAuthSessionResponse | null>();
}

export const __testables = {
  getSessionForBearer,
};

async function resolveProtectedAuthCookie(
  c: Context<{ Bindings: Env; Variables: { auth: AppAuth } }>,
  auth: AppAuth,
  accessToken: string,
) {
  const signedSessionToken = await loadSignedSessionTokenForBearer(c, auth, accessToken);
  if (signedSessionToken) {
    return `better-auth.session_token=${signedSessionToken}`;
  }

  const directCookie = await loadCurrentSessionCookie(c, auth, accessToken);
  if (directCookie) {
    return `better-auth.session_token=${directCookie}`;
  }

  return null;
}

async function loadCurrentSessionCookie(
  c: Context<{ Bindings: Env; Variables: { auth: AppAuth } }>,
  auth: AppAuth,
  accessToken: string,
) {
  const response = await callAuthEndpoint(c, auth, '/api/auth/get-session', {
    method: 'GET',
    accessToken,
    setCookieNames: ['better-auth.session_token'],
  });

  if (!response.ok) {
    return null;
  }

  const sessionCookie = extractCookieValue(response.headers.get('set-cookie'), 'better-auth.session_token');
  if (!sessionCookie) {
    return null;
  }

  return sessionCookie;
}

async function loadSignedSessionTokenForBearer(
  c: Context<{ Bindings: Env; Variables: { auth: AppAuth } }>,
  auth: AppAuth,
  accessToken: string,
) {
  const db = getDb(c.env);
  const matchingAccount = await db.query.account.findFirst({
    where: eq(schema.account.accessToken, accessToken),
    columns: {
      accountId: true,
      userId: true,
    },
  });

  if (!matchingAccount?.userId) {
    return null;
  }

  const matchingSession = await db.query.session.findFirst({
    where: eq(schema.session.userId, matchingAccount.userId),
    columns: {
      token: true,
      expiresAt: true,
    },
    orderBy: desc(schema.session.expiresAt),
  });

  if (!matchingSession?.token || !isSessionActive(matchingSession.expiresAt)) {
    return await loadSignedSessionTokenFromCurrentSessionCookie(c, auth, accessToken);
  }

  return await signCookieValue(matchingSession.token, c.env.BETTER_AUTH_SECRET);
}

async function loadSignedSessionTokenFromCurrentSessionCookie(
  c: Context<{ Bindings: Env; Variables: { auth: AppAuth } }>,
  auth: AppAuth,
  accessToken: string,
) {
  const response = await callAuthEndpoint(c, auth, '/api/auth/get-session', {
    method: 'GET',
    accessToken,
    setCookieNames: ['better-auth.session_token'],
  });

  if (!response.ok) {
    return null;
  }

  return extractCookieValue(response.headers.get('set-cookie'), 'better-auth.session_token');
}

async function loadSessionViaBearer(auth: AppAuth, accessToken: string) {
  const getSession = auth.api?.getSession;
  if (!getSession) {
    return null;
  }

  try {
    return await getSession({
      headers: new Headers({
        Authorization: `Bearer ${accessToken}`,
      }),
    }) as BetterAuthSessionResponse | null;
  } catch {
    return null;
  }
}

async function revokeBearerBackedSession(
  c: Context<{ Bindings: Env; Variables: { auth: AppAuth } }>,
  accessToken: string,
) {
  const db = getDb(c.env);
  const decodedToken = decodeAuthToken(accessToken);
  const matchingAccount = await db.query.account.findFirst({
    where: eq(schema.account.accountId, decodedToken),
    columns: {
      accountId: true,
    },
  });

  if (!matchingAccount?.accountId) {
    return false;
  }

  const deleted = await db.delete(schema.session)
    .where(eq(schema.session.token, matchingAccount.accountId))
    .returning({ token: schema.session.token });

  return deleted.length > 0;
}

function decodeAuthToken(accessToken: string) {
  try {
    return decodeURIComponent(accessToken).split('.', 1)[0] ?? accessToken;
  } catch {
    return accessToken.split('.', 1)[0] ?? accessToken;
  }
}

type BetterAuthSessionInventoryItem = {
  id: string;
  userId: string;
  token?: string | null;
  expiresAt: string | Date | null;
  createdAt?: string | Date | null;
  updatedAt?: string | Date | null;
  ipAddress?: string | null;
  userAgent?: string | null;
};

type BetterAuthDeviceSessionItem = {
  session: BetterAuthSessionInventoryItem;
  user: BetterAuthSessionResponse['user'];
};

type BetterAuthJWTResponse = {
  token: string;
};

type BetterAuthJWKSResponse = {
  keys: Array<Record<string, unknown>>;
};

function extractBearerToken(headers: Headers) {
  const authorization = headers.get('authorization');
  if (!authorization) {
    return null;
  }

  if (authorization.toLowerCase().startsWith('bearer ')) {
    return authorization.slice(7).trim();
  }

  return authorization.trim();
}

function extractMagicLinkError(urlString: string) {
  try {
    return new URL(urlString).searchParams.get('error') ?? 'UNKNOWN_ERROR';
  } catch {
    return 'UNKNOWN_ERROR';
  }
}

function extractCallbackError(urlString: string) {
  try {
    return new URL(urlString).searchParams.get('error');
  } catch {
    return null;
  }
}

function isRedirectStatus(status: number) {
  return status >= 300 && status < 400;
}

function getResponseLocation(response: Response) {
  return response.headers.get('Location') ?? response.headers.get('location') ?? response.url;
}

function isMagicLinkSuccessRedirect(response: Response) {
  if (!isRedirectStatus(response.status)) {
    return false;
  }

  return extractMagicLinkError(getResponseLocation(response)) === 'UNKNOWN_ERROR';
}

function isSuccessfulOAuthRedirect(response: Response) {
  if (!isRedirectStatus(response.status)) {
    return false;
  }

  const location = getResponseLocation(response);
  if (!location) {
    return true;
  }

  return !extractCallbackError(location);
}

function formatPasskey(passkey: BetterAuthPasskey) {
  return {
    id: passkey.id,
    name: passkey.name ?? null,
    publicKey: passkey.publicKey,
    userId: passkey.userId,
    credentialID: passkey.credentialID,
    counter: passkey.counter,
    deviceType: passkey.deviceType,
    backedUp: passkey.backedUp,
    transports: passkey.transports ?? null,
    createdAt: passkey.createdAt ? new Date(passkey.createdAt) : null,
    aaguid: passkey.aaguid ?? null,
  };
}

function isSessionActive(expiresAt: string | Date | null | undefined) {
  if (!expiresAt) {
    return true;
  }

  return new Date(expiresAt).getTime() > Date.now();
}

async function callPublicAuthEndpoint(
  c: Context<{ Bindings: Env; Variables: { auth: AppAuth } }>,
  auth: AppAuth,
  path: string,
  options: AuthEndpointOptions,
) {
  const headers = new Headers({
    origin: c.env.TRUSTED_ORIGIN,
  });

  if (options.cookie) {
    headers.set('cookie', options.cookie);
  }

  const init: RequestInit = {
    method: options.method,
    headers,
  };

  if (options.body !== undefined) {
    headers.set('content-type', 'application/json');
    init.body = JSON.stringify(options.body);
  }

  const request = new Request(new URL(path, c.env.BETTER_AUTH_URL), init);
  const response = await auth.handler(request);
  return withFilteredSetCookies(response, options.setCookieNames);
}

async function callAuthEndpoint(
  c: Context<{ Bindings: Env; Variables: { auth: AppAuth } }>,
  auth: AppAuth,
  path: string,
  options: {
    method: 'GET' | 'POST';
    accessToken: string;
    body?: unknown;
    cookie?: string | null;
    setCookieNames?: string[];
  },
) {
  const headers = new Headers({
    origin: c.env.TRUSTED_ORIGIN,
    Authorization: `Bearer ${options.accessToken}`,
  });

  if (options.cookie) {
    headers.set('cookie', options.cookie);
  }

  const init: RequestInit = {
    method: options.method,
    headers,
  };

  if (options.body !== undefined) {
    headers.set('content-type', 'application/json');
    init.body = JSON.stringify(options.body);
  }

  const request = new Request(new URL(path, c.env.BETTER_AUTH_URL), init);
  const response = await auth.handler(request);
  return withFilteredSetCookies(response, options.setCookieNames);
}

async function mapAuthFailure(response: Response) {
  return mapAuthFailureWithHeaders(response);
}

async function mapAuthFailureWithHeaders(response: Response, setCookies: string[] = []) {
  const status = response.status;
  const contentType = response.headers.get('content-type') ?? '';
  const headers = new Headers();
  for (const setCookie of setCookies) {
    headers.append('set-cookie', setCookie);
  }

  if (contentType.includes('application/json')) {
    const body = await response.json<unknown>();
    return Response.json(body, { status, headers });
  }

  const text = await response.text();
  const body = text.length > 0 ? { error: text } : { error: 'Unauthorized' };
  return Response.json(body, { status, headers });
}

async function mapEmailAuthContractFailure(response: Response) {
  const contentType = response.headers.get('content-type') ?? '';
  if (!contentType.includes('application/json')) {
    return null;
  }

  const body = await response.clone().json<{ code?: string; message?: string }>();
  if (response.status === 422 && body.code?.startsWith('USER_ALREADY_EXISTS')) {
    return Response.json({
      requiresVerification: false,
      user: null,
    });
  }

  if (response.status === 403 && body.code === 'EMAIL_NOT_VERIFIED') {
    return Response.json(body, { status: response.status });
  }

  return null;
}

async function handleEmailAuth(
  c: Context<{ Bindings: Env; Variables: { auth: AppAuth } }>,
  auth: AppAuth,
  path: string,
  payload: Record<string, unknown>,
  options?: {
    propagateTwoFactorChallengeCookie?: boolean;
  },
) {
  const authRequest = new Request(new URL(path, c.env.BETTER_AUTH_URL), {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      origin: c.env.TRUSTED_ORIGIN,
    },
    body: JSON.stringify(payload),
  });

  const authResponse = await auth.handler(authRequest);
  if (path === '/api/auth/sign-up/email') {
    return mapEmailAuthResponse(c, authResponse, auth);
  }

  if (options?.propagateTwoFactorChallengeCookie) {
    const twoFactorCookie = copySetCookie(authResponse.headers, 'better-auth.two_factor');
    const dontRememberCookie = copySetCookie(authResponse.headers, 'better-auth.dont_remember');
    if (twoFactorCookie || dontRememberCookie) {
      return mapAuthFailureWithHeaders(
        authResponse,
        [twoFactorCookie, dontRememberCookie].filter((value): value is string => Boolean(value)),
      );
    }
  }

  const mappedError = await mapEmailSignInFailure(authResponse);
  if (mappedError) {
    return mappedError;
  }

  const accessToken = authResponse.headers.get('set-auth-token');
  if (!accessToken) {
    return c.json({ error: 'Missing bearer token from Better Auth auth response.' }, 500);
  }

  const session = await getSessionForBearer(c, auth, accessToken);

  if (!session?.session || !session.user) {
    return c.json({ error: 'Unable to load Better Auth session.' }, 500);
  }

  return c.json(session);
}

async function mapTwoFactorChallengeResponse(
  c: Context<{ Bindings: Env; Variables: { auth: AppAuth } }>,
  auth: AppAuth,
  response: Response,
) {
  if (!response.ok) {
    return mapAuthFailure(response);
  }

  const body = await response.json<TwoFactorSessionResponse>();
  const headerToken = response.headers.get('set-auth-token');
  const bodyToken = typeof body.token === 'string' && body.token.length > 0 ? body.token : null;
  const bearer = headerToken ?? bodyToken;
  if (!bearer) {
    return c.json({
      token: null,
      user: {
        ...body.user,
        twoFactorEnabled: body.user.twoFactorEnabled ?? true,
      },
    });
  }

  const session = await getSessionForBearer(c, auth, bearer);
  if (!session?.session || !session.user) {
    return c.json({ error: 'Unable to load Better Auth session.' }, 500);
  }

  return c.json(session);
}

function splitSetCookieHeader(setCookieHeader: string) {
  const segments: string[] = [];
  let current = '';
  let inExpiresAttribute = false;

  for (let index = 0; index < setCookieHeader.length; index += 1) {
    const char = setCookieHeader[index];
    const remaining = setCookieHeader.slice(index).toLowerCase();

    if (!inExpiresAttribute && remaining.startsWith('expires=')) {
      inExpiresAttribute = true;
    }

    if (char === ',') {
      const remainder = setCookieHeader.slice(index + 1);
      const startsNextCookie = /^\s*[A-Za-z0-9_.-]+=/.test(remainder);
      if (!inExpiresAttribute && startsNextCookie) {
        segments.push(current.trim());
        current = '';
        continue;
      }
    }

    if (inExpiresAttribute && char === ';') {
      inExpiresAttribute = false;
    }

    current += char;
  }

  if (current.trim()) {
    segments.push(current.trim());
  }

  return segments;
}

function extractCookieValue(setCookieHeader: string | null, cookieName: string) {
  if (!setCookieHeader) {
    return null;
  }

  return splitSetCookieHeader(setCookieHeader)
    .find((segment) => segment.startsWith(`${cookieName}=`))
    ?.slice(cookieName.length + 1)
    .split(';', 1)[0] ?? null;
}

function copySetCookie(headers: Headers, cookieName: string) {
  const raw = headers.get('set-cookie');
  if (!raw) {
    return null;
  }

  return splitSetCookieHeader(raw)
    .find((segment) => segment.trim().startsWith(`${cookieName}=`)) ?? null;
}

function copySetCookies(headers: Headers) {
  const raw = headers.get('set-cookie');
  if (!raw) {
    return [];
  }

  return splitSetCookieHeader(raw)
    .map((segment) => segment.trim())
    .filter(Boolean);
}

function appendSetCookies(headers: Headers, cookies: string[]) {
  for (const cookie of cookies) {
    headers.append('set-cookie', cookie);
  }
  return headers;
}

function withFilteredSetCookies(response: Response, cookieNames?: string[]) {
  if (!cookieNames?.length) {
    return response;
  }

  const cookies = copySetCookies(response.headers)
    .filter((cookie) => cookieNames.some((name) => cookie.trim().startsWith(`${name}=`)));
  if (cookies.length === 0) {
    return response;
  }

  const headers = new Headers(response.headers);
  headers.delete('set-cookie');
  for (const cookie of cookies) {
    headers.append('set-cookie', cookie);
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function resolveCookieHeader(headers: Headers, cookieNames: string[]) {
  const cookies = cookieNames
    .map((name) => readNamedCookie(headers, name))
    .flatMap((value, index) => value ? [`${cookieNames[index]}=${value}`] : []);
  return cookies.length > 0 ? cookies.join('; ') : null;
}

function readNamedCookie(headers: Headers, cookieName: string) {
  const cookieHeader = headers.get('cookie');
  if (!cookieHeader) {
    return null;
  }

  const escapedCookieName = cookieName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const match = cookieHeader.match(new RegExp(`(?:^|;\\s*)${escapedCookieName}=([^;]+)`));
  return match?.[1] ?? null;
}

function readTwoFactorCookie(headers: Headers) {
  const cookieHeader = headers.get('cookie');
  if (!cookieHeader) {
    return null;
  }

  const match = cookieHeader.match(/(?:^|;\s*)better-auth\.two_factor=([^;]+)/);
  return match?.[1] ?? null;
}

async function materializeTwoFactorCookie(
  c: Context<{ Bindings: Env; Variables: { auth: AppAuth } }>,
  auth: AppAuth,
  accessToken: string,
) {
  const sessionResponse = await callAuthEndpoint(c, auth, '/api/auth/get-session', {
    method: 'GET',
    accessToken,
  });

  if (!sessionResponse.ok) {
    return null;
  }

  const sessionCookie = extractCookieValue(sessionResponse.headers.get('set-cookie'), 'better-auth.session_token');
  if (!sessionCookie) {
    return null;
  }

  const challengeResponse = await auth.handler(new Request(new URL('/api/auth/two-factor/send-otp', c.env.BETTER_AUTH_URL), {
    method: 'POST',
    headers: new Headers({
      origin: c.env.TRUSTED_ORIGIN,
      cookie: `better-auth.session_token=${sessionCookie}`,
      'content-type': 'application/json',
    }),
    body: JSON.stringify({}),
  }));

  if (!challengeResponse.ok) {
    return null;
  }

  const cookie = extractCookieValue(challengeResponse.headers.get('set-cookie'), 'better-auth.two_factor');
  if (!cookie) {
    return null;
  }

  return `better-auth.two_factor=${cookie}`;
}

async function resolveTwoFactorCookie(
  c: Context<{ Bindings: Env; Variables: { auth: AppAuth } }>,
  auth: AppAuth,
) {
  const existingCookie = readTwoFactorCookie(c.req.raw.headers);
  if (existingCookie) {
    return `better-auth.two_factor=${existingCookie}`;
  }

  const accessToken = extractBearerToken(c.req.raw.headers);
  if (!accessToken) {
    return null;
  }

  if (!(await isActiveBearer(c, accessToken))) {
    return null;
  }

  return materializeTwoFactorCookie(c, auth, accessToken);
}

async function resolveMultiSessionCookies(
  c: Context<{ Bindings: Env; Variables: { auth: AppAuth } }>,
  auth: AppAuth,
  accessToken: string,
  sessionToken?: string,
) {
  const sessionResponse = await callAuthEndpoint(c, auth, '/api/auth/get-session', {
    method: 'GET',
    accessToken,
  });

  if (!sessionResponse.ok) {
    return null;
  }

  const sessionCookie = extractCookieValue(sessionResponse.headers.get('set-cookie'), 'better-auth.session_token');
  if (!sessionCookie) {
    return null;
  }

  const listResponse = await callAuthEndpoint(c, auth, '/api/auth/list-sessions', {
    method: 'GET',
    accessToken,
  });
  if (!listResponse.ok) {
    return null;
  }

  const sessions = await listResponse.json<BetterAuthSessionInventoryItem[]>();
  const activeSessions = sessions.filter((session) => isSessionActive(session.expiresAt));
  if (!activeSessions.length) {
    return null;
  }

  const targetSessionTokens = sessionToken
    ? [sessionToken]
    : activeSessions.map((session) => session.token).filter((token): token is string => Boolean(token));

  if (!targetSessionTokens.length) {
    return null;
  }

  const cookieParts = ['better-auth.session_token=' + sessionCookie];
  const seenTokens = new Set<string>();
  for (const token of targetSessionTokens) {
    const normalizedToken = token.toLowerCase();
    if (seenTokens.has(normalizedToken)) {
      continue;
    }
    seenTokens.add(normalizedToken);
    cookieParts.push(`better-auth.session_token_multi-${normalizedToken}=${await signCookieValue(token, c.env.BETTER_AUTH_SECRET)}`);
  }

  return cookieParts.join('; ');
}

async function signCookieValue(value: string, secret: string) {
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

function extractURLFromValue(value: string) {
  const metadata = extractJSONMetadata(value);
  if (metadata && typeof (metadata as Record<string, unknown>).url === 'string') {
    return String((metadata as Record<string, unknown>).url);
  }

  const match = value.match(/https?:\/\/[^\s"]+/);
  return match?.[0];
}

function extractJSONMetadata(value: string) {
  try {
    return JSON.parse(value) as CaptureJSON;
  } catch {
    return undefined;
  }
}

function extractCaptureSignature(metadata: CaptureJSON | undefined) {
  return metadata && typeof (metadata as Record<string, unknown>).signature === 'string'
    ? String((metadata as Record<string, unknown>).signature)
    : undefined;
}

function inferCapture(identifier: string, value: string) {
  const url = extractURLFromValue(value);
  const json = extractJSONMetadata(value);

  if (identifier.startsWith('reset-password:')) {
    return {
      channel: 'password-reset' as const,
      token: identifier.slice('reset-password:'.length),
      email: typeof json?.email === 'string' ? json.email : undefined,
      newEmail: undefined,
      phoneNumber: undefined,
      otpType: undefined,
    };
  }

  if (identifier.startsWith('magic-link')) {
    return {
      channel: 'magic-link' as const,
      token: url ? new URL(url).searchParams.get('token') ?? identifier : identifier,
      email: typeof json?.email === 'string' ? json.email : undefined,
      newEmail: undefined,
      phoneNumber: undefined,
      otpType: undefined,
    };
  }

  if (identifier.includes('-otp-')) {
    const { channel, otpType, email: inferredEmail, newEmail: inferredNewEmail } = inferOTPIdentifier(identifier);
    const { email: metadataEmail, newEmail: metadataNewEmail } = inferOTPEmailsFromMetadata(json);
    const token = inferOTPToken(identifier, value, json);
    return {
      channel,
      token,
      email: metadataEmail ?? inferredEmail,
      newEmail: metadataNewEmail ?? inferredNewEmail,
      phoneNumber: undefined,
      otpType,
    };
  }

  if (identifier.startsWith('2fa-otp-')) {
    const token = typeof value === 'string' && value.includes(':') ? value.split(':', 1)[0] : value;
    return {
      channel: 'two-factor' as const,
      token,
      email: undefined,
      newEmail: undefined,
      phoneNumber: undefined,
      otpType: undefined,
    };
  }

  if (json && (typeof json.userId === 'string' || typeof json.email === 'string') && !url) {
    return {
      channel: 'two-factor' as const,
      token: typeof json.token === 'string' ? json.token : identifier,
      email: typeof json.email === 'string' ? json.email : undefined,
      newEmail: undefined,
      phoneNumber: undefined,
      otpType: undefined,
    };
  }

  if (identifier.startsWith('+')) {
    const token = typeof value === 'string' && value.includes(':') ? value.split(':', 1)[0] : value;
    return {
      channel: 'phone-number' as const,
      token,
      email: undefined,
      newEmail: undefined,
      phoneNumber: identifier,
      otpType: undefined,
    };
  }

  if (url?.includes('/verify-email')) {
    const parsed = new URL(url);
    const requestType = parsed.searchParams.get('requestType');
    return {
      channel: requestType === 'change-email-confirmation'
        ? 'change-email-confirmation' as const
        : requestType === 'change-email-verification'
          ? 'change-email-verification' as const
          : 'email-verification' as const,
      token: parsed.searchParams.get('token') ?? identifier,
      email: typeof json?.email === 'string'
        ? json.email
        : typeof json?.user?.email === 'string'
          ? json.user.email
          : undefined,
      newEmail: parsed.searchParams.get('updateTo') ?? undefined,
      phoneNumber: undefined,
      otpType: undefined,
    };
  }

  return {
    channel: 'email-verification' as const,
    token: identifier,
    email: undefined,
    newEmail: undefined,
    phoneNumber: undefined,
    otpType: undefined,
  };
}

function inferOTPIdentifier(identifier: string) {
  if (identifier.startsWith('email-verification-otp-')) {
    return {
      channel: 'email-otp' as const,
      otpType: 'email-verification',
      email: identifier.slice('email-verification-otp-'.length),
      newEmail: undefined,
    };
  }

  if (identifier.startsWith('sign-in-otp-')) {
    return {
      channel: 'email-otp' as const,
      otpType: 'sign-in',
      email: identifier.slice('sign-in-otp-'.length),
      newEmail: undefined,
    };
  }

  if (identifier.startsWith('forget-password-otp-')) {
    return {
      channel: 'email-otp' as const,
      otpType: 'forget-password',
      email: identifier.slice('forget-password-otp-'.length),
      newEmail: undefined,
    };
  }

  if (identifier.startsWith('change-email-otp-')) {
    return inferChangeEmailOTPIdentifier(identifier);
  }

  const parts = identifier.split(':');
  const otpType = parts[1];
  const email = parts.slice(2).join(':') || undefined;
  return {
    channel: 'email-otp' as const,
    otpType,
    email,
    newEmail: undefined,
  };
}

function inferChangeEmailOTPIdentifier(identifier: string) {
  const suffix = identifier.slice('change-email-otp-'.length);
  const atIndices = Array.from(suffix.matchAll(/@/g), (match) => match.index).filter((index): index is number => index !== undefined);

  for (const atIndex of atIndices) {
    const separatorIndex = suffix.indexOf('-', atIndex);
    if (separatorIndex < 0) {
      continue;
    }

    const email = suffix.slice(0, separatorIndex);
    const newEmail = suffix.slice(separatorIndex + 1);
    if (email.includes('@') && newEmail.includes('@')) {
      return {
        channel: 'change-email-verification' as const,
        otpType: 'change-email',
        email,
        newEmail,
      };
    }
  }

  return {
    channel: 'change-email-verification' as const,
    otpType: 'change-email',
    email: undefined,
    newEmail: undefined,
  };
}

function inferOTPToken(identifier: string, value: string, json: CaptureJSON | undefined) {
  if (typeof json?.otp === 'string') {
    return json.otp;
  }

  if (typeof json?.token === 'string') {
    return json.token;
  }

  if (typeof json?.code === 'string') {
    return json.code;
  }

  const prefix = value.split(':')[0];
  if (!prefix || prefix === value) {
    return identifier;
  }

  return prefix;
}

function inferOTPEmailsFromMetadata(json: CaptureJSON | undefined) {
  return {
    email: typeof json?.email === 'string' ? json.email : undefined,
    newEmail: typeof json?.newEmail === 'string' ? json.newEmail : undefined,
  };
}
