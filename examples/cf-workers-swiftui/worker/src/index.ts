import { Hono } from 'hono';
import type { IncomingRequestCfProperties } from '@cloudflare/workers-types';
import { createAuth, repairLocalD1AuthSchema } from './auth';
import { appRoutes } from './routes/app';
import type { Env } from './types';

const app = new Hono<{ Bindings: Env; Variables: { auth: Awaited<ReturnType<typeof createAuth>> } }>();

type AppBootstrap = Awaited<ReturnType<typeof createAppBootstrap>>;

let bootstrapPromise: Promise<AppBootstrap> | null = null;

export function resetAppBootstrapForTests() {
  bootstrapPromise = null;
}

async function createAppBootstrap(env: Env, cf?: IncomingRequestCfProperties) {
  await repairLocalD1AuthSchema(env.DB);
  const auth = await createAuth(env, cf);
  return { auth };
}

function getAppBootstrap(env: Env, cf?: IncomingRequestCfProperties) {
  bootstrapPromise ??= createAppBootstrap(env, cf);
  return bootstrapPromise;
}

const requiresAuthBootstrap = /^\/(?:api\/auth(?:\/|$)|api\/fixtures\/captures(?:\/|$)|api\/me(?:\/|$))/;

app.use('*', async (c, next) => {
  if (!requiresAuthBootstrap.test(c.req.path)) {
    await next();
    return;
  }

  const { auth } = await getAppBootstrap(c.env, c.req.raw.cf as IncomingRequestCfProperties | undefined);
  c.set('auth', auth);
  await next();
});

app.route('/', appRoutes);

app.all('/api/auth/*', async (c) => {
  const auth = c.get('auth');
  return auth.handler(c.req.raw);
});

export default app;
