export interface Env {
  DB: D1Database;
  BETTER_AUTH_URL: string;
  BETTER_AUTH_SECRET: string;
  APPLE_AUTH_MODE?: 'real' | 'emulated';
  APPLE_CLIENT_ID: string;
  APPLE_APP_BUNDLE_IDENTIFIER: string;
  APPLE_TEAM_ID: string;
  APPLE_KEY_ID: string;
  APPLE_PRIVATE_KEY: string;
  APPLE_EMULATOR_BASE_URL?: string;
  TRUSTED_ORIGIN: string;
  FIXTURE_CAPTURE_SECRET?: string;
  EMAIL_OTP_DISABLE_SIGN_UP?: string;
  EMAIL_OTP_RUNTIME_MODE?: 'sign-up-enabled' | 'sign-up-disabled';
  GENERIC_OAUTH_ISSUER?: string;
  GENERIC_OAUTH_AUTHORIZATION_URL?: string;
  GENERIC_OAUTH_TOKEN_URL?: string;
  GENERIC_OAUTH_USERINFO_URL?: string;
}
