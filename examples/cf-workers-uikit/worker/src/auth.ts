import type { IncomingRequestCfProperties } from '@cloudflare/workers-types';
import { betterAuth } from 'better-auth';
import { bearer } from 'better-auth/plugins';
import { emailOTP } from 'better-auth/plugins/email-otp';
import { magicLink } from 'better-auth/plugins/magic-link';
import { phoneNumber } from 'better-auth/plugins/phone-number';
import { twoFactor } from 'better-auth/plugins/two-factor';
import { anonymous, genericOAuth, jwt, multiSession, username } from 'better-auth/plugins';
import { passkey } from '@better-auth/passkey';
import { drizzleAdapter } from 'better-auth/adapters/drizzle';
import { withCloudflare } from 'better-auth-cloudflare';
import { drizzle } from 'drizzle-orm/d1';
import { createRemoteJWKSet, decodeJwt, importPKCS8, jwtVerify, SignJWT } from 'jose';
import type { Env } from './types';
import { schema } from './db/schema';

const applePrivateKeyPlaceholder = 'REPLACE_ME';

type CapturedFixturePayload = {
  channel:
    | 'email-verification'
    | 'password-reset'
    | 'change-email-confirmation'
    | 'change-email-verification'
    | 'magic-link'
    | 'email-otp'
    | 'phone-number'
    | 'two-factor'
    | 'delete-account';
  token: string;
  identifier?: string;
  email?: string;
  newEmail?: string;
  phoneNumber?: string;
  otpType?: string;
  url?: string;
  userId?: string;
  metadata?: Record<string, unknown>;
};

function normalizeFixtureIdentifier(payload: CapturedFixturePayload) {
  if (payload.channel === 'email-otp') {
    const email = payload.email?.toLowerCase();
    const otpType = payload.otpType ?? 'sign-in';
    if (email) {
      return `email-otp:${otpType}:${email}`;
    }
  }

  if (payload.identifier) {
    return payload.identifier;
  }

  return payload.token;
}

function normalizeCaptureSecret(env: Env) {
  return env.FIXTURE_CAPTURE_SECRET ?? env.BETTER_AUTH_SECRET;
}

async function signFixtureCapture(env: Env, payload: CapturedFixturePayload) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(normalizeCaptureSecret(env)),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const body = encoder.encode(JSON.stringify(payload));
  const signature = await crypto.subtle.sign('HMAC', key, body);

  return Buffer.from(signature).toString('base64url');
}

export async function buildFixtureCapture(env: Env, payload: CapturedFixturePayload) {
  const identifier = normalizeFixtureIdentifier(payload);
  const capture = {
    ...payload,
    identifier,
    signature: await signFixtureCapture(env, payload),
  };

  await persistFixtureCapture(env, capture);

  return capture;
}

async function persistFixtureCapture(
  env: Env,
  payload: CapturedFixturePayload & {
    identifier: string;
    signature: string;
  },
) {
  if (!env.DB || typeof env.DB.prepare !== 'function') {
    return;
  }

  const storedValue = JSON.stringify({
    channel: payload.channel,
    token: payload.token,
    email: payload.email,
    newEmail: payload.newEmail,
    phoneNumber: payload.phoneNumber,
    otpType: payload.otpType,
    url: payload.url,
    userId: payload.userId,
    metadata: payload.metadata,
    signature: payload.signature,
  });

  const id = crypto.randomUUID();
  const expiresAt = Date.now() + 1000 * 60 * 60 * 24;

  await env.DB.prepare(
    `INSERT INTO "verification" ("id", "identifier", "value", "expires_at", "created_at", "updated_at")
     VALUES (?, ?, ?, ?, ?, ?)`,
  ).bind(id, payload.identifier, storedValue, expiresAt, Date.now(), Date.now()).run();
}

const decodePrivateKey = (privateKey: string) => privateKey.replace(/\\n/g, '\n');

export async function generateAppleClientSecret(env: Env) {
  if (!env.APPLE_PRIVATE_KEY || env.APPLE_PRIVATE_KEY.includes(applePrivateKeyPlaceholder)) {
    return undefined;
  }

  const key = await importPKCS8(decodePrivateKey(env.APPLE_PRIVATE_KEY), 'ES256');
  const now = Math.floor(Date.now() / 1000);

  return new SignJWT({})
    .setProtectedHeader({ alg: 'ES256', kid: env.APPLE_KEY_ID })
    .setIssuer(env.APPLE_TEAM_ID)
    .setSubject(env.APPLE_CLIENT_ID)
    .setAudience('https://appleid.apple.com')
    .setIssuedAt(now)
    .setExpirationTime(now + 60 * 60)
    .sign(key);
}

export function getAppleAuthBaseURL(env: Pick<Env, 'APPLE_AUTH_MODE' | 'APPLE_AUTH_PROXY_BASE_URL' | 'APPLE_EMULATOR_BASE_URL'>) {
  if ((env.APPLE_AUTH_MODE ?? 'real') === 'emulated') {
    return (env.APPLE_EMULATOR_BASE_URL ?? 'http://127.0.0.1:4010').replace(/\/$/, '');
  }

  if (env.APPLE_AUTH_PROXY_BASE_URL) {
    return env.APPLE_AUTH_PROXY_BASE_URL.replace(/\/$/, '');
  }

  return 'https://appleid.apple.com';
}

function isEmulatedApple(env: Env) {
  return (env.APPLE_AUTH_MODE ?? 'real') === 'emulated';
}

function getEmulatorIssuer(env: Env) {
  const configured = (env.APPLE_EMULATOR_BASE_URL ?? 'http://127.0.0.1:4010').replace(/\/$/, '');
  try {
    const url = new URL(configured);
    if (url.hostname === '127.0.0.1') {
      url.hostname = 'localhost';
    }
    return url.toString().replace(/\/$/, '');
  } catch {
    return configured;
  }
}

export async function verifyEmulatedAppleIdToken(
  env: Env,
  token: string,
  nonce?: string,
) {
  const issuer = getEmulatorIssuer(env);
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

type GenericProviderToken = {
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

export async function verifyFixtureGoogleIdToken(_token: string, nonce?: string) {
  return nonce !== 'mismatch';
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

type AuthorizationURLInput = {
  state: string;
  redirectURI: string;
  scopes?: string[];
  loginHint?: string;
};

export async function createAuth(env: Env, cf?: IncomingRequestCfProperties) {
  const db = drizzle(env.DB, { schema });
  const appleClientSecret = isEmulatedApple(env) ? undefined : await generateAppleClientSecret(env);

  return createAuthInstance({ env, db, appleClientSecret, cf });
}

type CreateAuthInstanceOptions = {
  env: Env;
  db?: ReturnType<typeof drizzle>;
  appleClientSecret?: string;
  cf?: IncomingRequestCfProperties;
};

export function createAuthInstance({
  env,
  db = drizzle(env.DB, { schema }),
  appleClientSecret,
  cf,
}: CreateAuthInstanceOptions) {
  return betterAuth({
    ...withCloudflare(
      {
        autoDetectIpAddress: true,
        geolocationTracking: false,
        cf: cf ?? {},
        d1: {
          db: db as never,
        },
      },
      {
        plugins: [
          bearer(),
          passkey({
            rpID: '127.0.0.1',
            rpName: 'Better Auth Swift',
            origin: env.TRUSTED_ORIGIN,
          }),
          magicLink({
            sendMagicLink: async ({ email, url, token, metadata }) => {
              await buildFixtureCapture(env, {
                channel: 'magic-link',
                token,
                email,
                url,
                metadata: metadata as Record<string, unknown> | undefined,
              });
            },
          }),
          emailOTP({
            disableSignUp: (
              env.EMAIL_OTP_RUNTIME_MODE
                ? env.EMAIL_OTP_RUNTIME_MODE === 'sign-up-disabled'
                : env.EMAIL_OTP_DISABLE_SIGN_UP === 'true'
            ),
            sendVerificationOTP: async ({ email, otp, type }) => {
              const runtimeMode = env.EMAIL_OTP_RUNTIME_MODE
                ?? (env.EMAIL_OTP_DISABLE_SIGN_UP === 'true' ? 'sign-up-disabled' : 'sign-up-enabled');
              await buildFixtureCapture(env, {
                channel: 'email-otp',
                token: otp,
                email,
                otpType: type,
                metadata: {
                  runtimeMode,
                },
              });
            },
          }),
          phoneNumber({
            sendOTP: async ({ phoneNumber, code }) => {
              await buildFixtureCapture(env, {
                channel: 'phone-number',
                token: code,
                phoneNumber,
                identifier: phoneNumber,
              });
            },
            sendPasswordResetOTP: async ({ phoneNumber, code }) => {
              await buildFixtureCapture(env, {
                channel: 'phone-number',
                token: code,
                phoneNumber,
                identifier: `reset:${phoneNumber}`,
                metadata: { purpose: 'password-reset' },
              });
            },
          }),
          twoFactor({
            otpOptions: {
              sendOTP: async ({ user, otp }) => {
                await buildFixtureCapture(env, {
                  channel: 'two-factor',
                  token: otp,
                  email: user.email ?? undefined,
                  userId: user.id,
                  identifier: user.id,
                });
              },
            },
          }),
          multiSession(),
          anonymous(),
          jwt(),
          genericOAuth({
            config: [{
              providerId: 'fixture-generic',
              issuer: env.GENERIC_OAUTH_ISSUER ?? 'https://fixture-oauth.example.com',
              authorizationUrl: env.GENERIC_OAUTH_AUTHORIZATION_URL ?? 'https://fixture-oauth.example.com/oauth/authorize',
              tokenUrl: env.GENERIC_OAUTH_TOKEN_URL ?? 'https://fixture-oauth.example.com/oauth/token',
              userInfoUrl: env.GENERIC_OAUTH_USERINFO_URL ?? 'https://fixture-oauth.example.com/oauth/userinfo',
              clientId: 'fixture-generic-client-id',
              clientSecret: 'fixture-generic-client-secret',
              scopes: ['openid', 'email', 'profile'],
              async getToken({ code }) {
                if (code !== 'fixture-code') {
                  throw new Error('Invalid fixture OAuth code');
                }
                return {
                  accessToken: 'fixture-generic-access-token',
                  refreshToken: 'fixture-generic-refresh-token',
                  idToken: 'fixture-generic-id-token',
                  scopes: ['openid', 'email', 'profile'],
                };
              },
              async getUserInfo() {
                return {
                  id: 'fixture-generic-user',
                  email: 'fixture-generic@example.com',
                  emailVerified: true,
                  name: 'Fixture Generic OAuth User',
                };
              },
            }],
          }),
          username(),
        ],
        database: drizzleAdapter(db as never, {
          provider: 'sqlite',
        }),
        secret: env.BETTER_AUTH_SECRET,
        baseURL: env.BETTER_AUTH_URL,
        trustedOrigins: [env.TRUSTED_ORIGIN, 'https://appleid.apple.com'],
        emailAndPassword: {
          enabled: true,
          requireEmailVerification: true,
          sendResetPassword: async ({ user, url, token }) => {
            await buildFixtureCapture(env, {
              channel: 'password-reset',
              token,
              email: user.email ?? undefined,
              userId: user.id,
              url,
              identifier: user.email?.toLowerCase(),
            });
          },
        },
        emailVerification: {
          sendVerificationEmail: async ({ user, url, token }) => {
            const parsedURL = new URL(url);
            const callbackToken = parsedURL.searchParams.get('token') ?? token;
            const newEmail = parsedURL.searchParams.get('updateTo') ?? undefined;
            const requestType = parsedURL.searchParams.get('requestType') ?? undefined;
            const channel = requestType === 'change-email-confirmation'
              ? 'change-email-confirmation'
              : requestType === 'change-email-verification'
                ? 'change-email-verification'
                : 'email-verification';

            await buildFixtureCapture(env, {
              channel,
              token: callbackToken,
              email: user.email ?? undefined,
              newEmail,
              userId: user.id,
              url,
              identifier: user.email?.toLowerCase(),
              metadata: requestType ? { requestType } : undefined,
            });
          },
        },
        user: {
          changeEmail: {
            enabled: true,
            sendChangeEmailConfirmation: async ({ user, newEmail, url, token }) => {
              await buildFixtureCapture(env, {
                channel: 'change-email-confirmation',
                token,
                email: user.email ?? undefined,
                newEmail,
                userId: user.id,
                url,
                identifier: user.email?.toLowerCase(),
              });
            },
          },
          deleteUser: {
            enabled: true,
            sendDeleteAccountVerification: async ({ user, url, token }) => {
              await buildFixtureCapture(env, {
                channel: 'delete-account',
                token,
                email: user.email ?? undefined,
                userId: user.id,
                url,
                identifier: user.email?.toLowerCase() ?? `delete-account:${user.id}`,
              });
            },
          },
        },
        session: {
          cookieCache: {
            enabled: false,
            cookieRefreshCache: 0,
          },
        },
        socialProviders: {
          apple: {
            clientId: env.APPLE_CLIENT_ID,
            clientSecret: appleClientSecret,
            appBundleIdentifier: env.APPLE_APP_BUNDLE_IDENTIFIER,
            audience: env.APPLE_APP_BUNDLE_IDENTIFIER || env.APPLE_CLIENT_ID,
            verifyIdToken: isEmulatedApple(env)
              ? (token, nonce) => verifyEmulatedAppleIdToken(env, token, nonce)
              : undefined,
            getUserInfo: isEmulatedApple(env)
              ? async (token) => getEmulatedAppleUserInfo(token)
              : undefined,
          },
          google: {
            clientId: 'fixture-google-client-id',
            clientSecret: 'fixture-google-client-secret',
            verifyIdToken: verifyFixtureGoogleIdToken,
            getUserInfo: getFixtureGoogleUserInfo,
            async createAuthorizationURL({ state, redirectURI, scopes, loginHint }: AuthorizationURLInput) {
              const url = new URL('https://accounts.google.com/o/oauth2/v2/auth');
              url.searchParams.set('client_id', 'fixture-google-client-id');
              url.searchParams.set('redirect_uri', redirectURI);
              url.searchParams.set('response_type', 'code');
              url.searchParams.set('scope', (scopes?.length ? scopes : ['openid', 'email', 'profile']).join(' '));
              url.searchParams.set('state', state);
              if (loginHint) {
                url.searchParams.set('login_hint', loginHint);
              }
              return url;
            },
          },
          github: {
            clientId: 'fixture-github-client-id',
            clientSecret: 'fixture-github-client-secret',
            disableIdTokenSignIn: true,
            async createAuthorizationURL({ state, redirectURI, scopes }: AuthorizationURLInput) {
              const url = new URL('https://github.com/login/oauth/authorize');
              url.searchParams.set('client_id', 'fixture-github-client-id');
              url.searchParams.set('redirect_uri', redirectURI);
              url.searchParams.set('scope', (scopes?.length ? scopes : ['read:user', 'user:email']).join(' '));
              url.searchParams.set('state', state);
              return url;
            },
          },
        },
        account: {
          accountLinking: {
            enabled: true,
            trustedProviders: ['google', 'apple'],
          },
        },
      },
    ),
  });
}

type ColumnDefinition = {
  name: string;
  type: string;
  notNull: boolean;
  defaultValue?: string;
};

type TableDefinition = {
  name: string;
  createSQL: string;
  indexes?: string[];
  uniqueIndexes?: string[];
};

const requiredUserColumns: ColumnDefinition[] = [
  {
    name: 'phone_number',
    type: 'TEXT',
    notNull: false,
  },
  {
    name: 'phone_number_verified',
    type: 'INTEGER',
    notNull: false,
  },
  {
    name: 'two_factor_enabled',
    type: 'INTEGER',
    notNull: true,
    defaultValue: '0',
  },
  {
    name: 'is_anonymous',
    type: 'INTEGER',
    notNull: false,
    defaultValue: '0',
  },
  {
    name: 'username',
    type: 'TEXT',
    notNull: false,
  },
  {
    name: 'display_username',
    type: 'TEXT',
    notNull: false,
  },
];

const requiredTables: TableDefinition[] = [
  {
    name: 'two_factor',
    createSQL: `CREATE TABLE IF NOT EXISTS "two_factor" (
  "id" TEXT PRIMARY KEY NOT NULL,
  "secret" TEXT NOT NULL,
  "backup_codes" TEXT NOT NULL,
  "user_id" TEXT NOT NULL,
  FOREIGN KEY ("user_id") REFERENCES "user"("id") ON DELETE cascade
)`,
    indexes: [
      'CREATE INDEX IF NOT EXISTS "twoFactor_secret_idx" ON "two_factor" ("secret")',
      'CREATE INDEX IF NOT EXISTS "twoFactor_userId_idx" ON "two_factor" ("user_id")',
    ],
  },
  {
    name: 'user',
    createSQL: `CREATE TABLE IF NOT EXISTS "user" (
  "id" TEXT PRIMARY KEY NOT NULL
)`,
    uniqueIndexes: [
      'CREATE UNIQUE INDEX IF NOT EXISTS "user_phone_number_unique" ON "user" ("phone_number")',
      'CREATE UNIQUE INDEX IF NOT EXISTS "user_username_unique" ON "user" ("username")',
    ],
  },
];

function quoteIdentifier(identifier: string) {
  return `"${identifier.replace(/"/g, '""')}"`;
}

async function getExistingColumns(database: D1Database, tableName: string) {
  const result = await database.prepare(`PRAGMA table_info(${quoteIdentifier(tableName)})`).all<{
    name: string;
  }>();

  return new Set(
    Array.isArray(result.results)
      ? result.results
          .map((row) => row?.name)
          .filter((name): name is string => typeof name === 'string')
      : [],
  );
}

async function addMissingColumns(
  database: D1Database,
  tableName: string,
  requiredColumns: ColumnDefinition[],
) {
  const existingColumns = await getExistingColumns(database, tableName);

  for (const column of requiredColumns) {
    if (existingColumns.has(column.name)) {
      continue;
    }

    const fragments = [
      `ALTER TABLE ${quoteIdentifier(tableName)}`,
      `ADD COLUMN ${quoteIdentifier(column.name)}`,
      column.type,
    ];

    if (column.defaultValue !== undefined) {
      fragments.push(`DEFAULT ${column.defaultValue}`);
    }

    if (column.notNull) {
      fragments.push('NOT NULL');
    }

    await database.prepare(fragments.join(' ')).run();
  }
}

async function listTables(database: D1Database) {
  const result = await database.prepare(
    `SELECT "name" FROM sqlite_master WHERE type = 'table'`,
  ).all<{ name: string }>();

  return new Set(
    Array.isArray(result.results)
      ? result.results
          .map((row) => row?.name)
          .filter((name): name is string => typeof name === 'string')
      : [],
  );
}

async function listIndexes(database: D1Database, tableName: string) {
  const result = await database.prepare(`PRAGMA index_list(${quoteIdentifier(tableName)})`).all<{
    name: string;
  }>();

  return new Set(
    Array.isArray(result.results)
      ? result.results
          .map((row) => row?.name)
          .filter((name): name is string => typeof name === 'string')
      : [],
  );
}

async function addMissingTables(database: D1Database, tables: TableDefinition[]) {
  const existingTables = await listTables(database);

  for (const table of tables) {
    if (!existingTables.has(table.name)) {
      await database.prepare(table.createSQL).run();
    }

    for (const indexSQL of table.indexes ?? []) {
      await database.prepare(indexSQL).run();
    }

    const existingIndexes = await listIndexes(database, table.name);
    for (const indexSQL of table.uniqueIndexes ?? []) {
      const match = indexSQL.match(/INDEX IF NOT EXISTS\\s+"([^"]+)"/i);
      const indexName = match?.[1];
      if (indexName && existingIndexes.has(indexName)) {
        continue;
      }
      await database.prepare(indexSQL).run();
    }
  }
}

export async function repairLocalD1AuthSchema(database: D1Database) {
  if (!database || typeof (database as Partial<D1Database>).prepare !== 'function') {
    return;
  }

  await addMissingColumns(database, 'user', requiredUserColumns);
  await addMissingTables(database, requiredTables);
}

export type AppAuth = Awaited<ReturnType<typeof createAuth>>;

const auth = createAuthInstance({
  env: {
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
    FIXTURE_CAPTURE_SECRET: 'dev-secret-change-me-32-chars-minimum',
  },
});

export default auth;

