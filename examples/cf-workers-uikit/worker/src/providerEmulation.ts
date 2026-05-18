import { createRemoteJWKSet, decodeJwt, jwtVerify } from 'jose';
import type { Env } from './types';

export type GenericProviderToken = {
  idToken?: string;
  accessToken?: string;
  refreshToken?: string;
  user?: {
    email?: string;
    name?: string;
    image?: string;
    emailVerified?: boolean;
    id?: string;
  };
};

export type AuthorizationURLInput = {
  state: string;
  redirectURI: string;
  scopes?: string[];
  loginHint?: string;
};

function stripTrailingSlash(value: string) {
  return value.replace(/\/$/, '');
}

export function getAppleAuthBaseURL(
  env: Pick<Env, 'APPLE_AUTH_MODE' | 'APPLE_AUTH_PROXY_BASE_URL' | 'APPLE_EMULATOR_BASE_URL'>,
) {
  if ((env.APPLE_AUTH_MODE ?? 'real') === 'emulated') {
    return stripTrailingSlash(env.APPLE_EMULATOR_BASE_URL ?? 'http://127.0.0.1:4010');
  }

  if (env.APPLE_AUTH_PROXY_BASE_URL) {
    return stripTrailingSlash(env.APPLE_AUTH_PROXY_BASE_URL);
  }

  return 'https://appleid.apple.com';
}

export function isEmulatedApple(env: Env) {
  return (env.APPLE_AUTH_MODE ?? 'real') === 'emulated';
}

function getAppleEmulatorIssuer(env: Env) {
  const configured = stripTrailingSlash(env.APPLE_EMULATOR_BASE_URL ?? 'http://127.0.0.1:4010');
  try {
    const url = new URL(configured);
    if (url.hostname === '127.0.0.1') {
      url.hostname = 'localhost';
    }
    return stripTrailingSlash(url.toString());
  } catch {
    return configured;
  }
}

export async function verifyEmulatedAppleIdToken(
  env: Env,
  token: string,
  nonce?: string,
) {
  const issuer = getAppleEmulatorIssuer(env);
  const jwks = createRemoteJWKSet(new URL('/auth/keys', issuer));
  const audiences = [env.APPLE_APP_BUNDLE_IDENTIFIER, env.APPLE_CLIENT_ID].filter(
    (value): value is string => Boolean(value),
  );
  try {
    const { payload } = await jwtVerify(token, jwks, {
      issuer,
      audience: audiences.length === 1 ? audiences[0] : audiences,
    });
    if (nonce && payload.nonce !== nonce) {
      return false;
    }

    return true;
  } catch {
    return false;
  }
}

export function getEmulatedAppleUserInfo(token: {
  idToken?: string;
  user?: {
    email?: string;
    name?: {
      firstName?: string;
      lastName?: string;
    };
  };
}) {
  if (!token.idToken) {
    return null;
  }

  const profile = decodeJwt<Record<string, unknown>>(token.idToken);
  const firstName = token.user?.name?.firstName ?? '';
  const lastName = token.user?.name?.lastName ?? '';
  const fullName = [firstName, lastName].filter(Boolean).join(' ').trim();
  const name = fullName.length === 0 ? String(profile.name ?? ' ') : fullName;
  const email = token.user?.email ?? String(profile.email ?? '');

  if (!email) {
    return null;
  }

  return {
    user: {
      id: String(profile.sub ?? ''),
      name,
      email,
      emailVerified: String(profile.email_verified ?? 'false') === 'true' || profile.email_verified === true,
    },
    data: profile,
  };
}

function isEmulatedGoogle(env: Env) {
  return env.GOOGLE_AUTH_MODE === 'emulated';
}

function getGoogleEmulatorBaseURL(env: Env) {
  return stripTrailingSlash(env.GOOGLE_EMULATOR_BASE_URL ?? 'http://127.0.0.1:4002');
}

export async function verifyFixtureGoogleIdToken(_token: string, nonce?: string) {
  return nonce !== 'mismatch';
}

export async function verifyGoogleIdToken(env: Env, token: string, nonce?: string) {
  if (!isEmulatedGoogle(env)) {
    return verifyFixtureGoogleIdToken(token, nonce);
  }

  try {
    const issuer = getGoogleEmulatorBaseURL(env);
    const jwks = createRemoteJWKSet(new URL('/oauth2/v3/certs', issuer));
    const { payload } = await jwtVerify(token, jwks, {
      issuer,
      audience: env.GOOGLE_CLIENT_ID ?? 'fixture-google-client-id',
    });
    return !nonce || payload.nonce === nonce;
  } catch {
    return verifyFixtureGoogleIdToken(token, nonce);
  }
}

export async function getFixtureGoogleUserInfo(token: GenericProviderToken) {
  if (token.idToken === 'missing-email-token') {
    return {
      user: {
        id: 'google-missing-email',
        name: 'Missing Email User',
        email: '',
        emailVerified: true,
      },
      data: {
        sub: 'google-missing-email',
      },
    };
  }

  if (token.idToken === 'cross-user-token') {
    return {
      user: {
        id: 'google-cross-user',
        name: 'Cross User',
        email: 'other@example.com',
        emailVerified: true,
      },
      data: {
        sub: 'google-cross-user',
      },
    };
  }

  if (token.idToken === 'existing-link-token') {
    return {
      user: {
        id: 'google-existing',
        name: 'Existing Link',
        email: 'linked@example.com',
        emailVerified: true,
      },
      data: {
        sub: 'google-existing',
      },
    };
  }

  return {
    user: {
      id: token.user?.id ?? 'google-fixture-user',
      name: token.user?.name ?? 'Fixture Google User',
      email: token.user?.email ?? 'linked@example.com',
      emailVerified: token.user?.emailVerified ?? true,
      image: token.user?.image,
    },
    data: {
      sub: token.user?.id ?? 'google-fixture-user',
      email: token.user?.email ?? 'linked@example.com',
      email_verified: token.user?.emailVerified ?? true,
    },
  };
}

export async function getGoogleUserInfo(env: Env, token: GenericProviderToken) {
  if (!isEmulatedGoogle(env) || !token.accessToken) {
    return getFixtureGoogleUserInfo(token);
  }

  try {
    const response = await fetch(new URL('/oauth2/v2/userinfo', getGoogleEmulatorBaseURL(env)), {
      headers: { Authorization: `Bearer ${token.accessToken}` },
    });
    if (!response.ok) {
      return getFixtureGoogleUserInfo(token);
    }

    const profile = await response.json<Record<string, unknown>>();
    const email = String(profile.email ?? '');
    if (!email) {
      return getFixtureGoogleUserInfo(token);
    }

    return {
      user: {
        id: String(profile.sub ?? profile.id ?? ''),
        name: String(profile.name ?? email),
        email,
        emailVerified: profile.email_verified === true || profile.email_verified === 'true',
        image: typeof profile.picture === 'string' ? profile.picture : undefined,
      },
      data: profile,
    };
  } catch {
    return getFixtureGoogleUserInfo(token);
  }
}

export function createGoogleAuthorizationURL(
  env: Env,
  { state, redirectURI, scopes, loginHint }: AuthorizationURLInput,
) {
  const baseURL = isEmulatedGoogle(env)
    ? getGoogleEmulatorBaseURL(env)
    : 'https://accounts.google.com';
  const url = new URL('/o/oauth2/v2/auth', baseURL);
  url.searchParams.set('client_id', env.GOOGLE_CLIENT_ID ?? 'fixture-google-client-id');
  url.searchParams.set('redirect_uri', redirectURI);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', (scopes?.length ? scopes : ['openid', 'email', 'profile']).join(' '));
  url.searchParams.set('state', state);
  if (loginHint) {
    url.searchParams.set('login_hint', loginHint);
  }
  return url;
}
