import { drizzle } from 'drizzle-orm/d1';
import type { Env } from '../types';
import { schema } from './schema';

export const getDb = (env: Pick<Env, 'DB'>) => drizzle(env.DB, { schema });
