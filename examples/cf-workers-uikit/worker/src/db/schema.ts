import { integer, sqliteTable, text } from 'drizzle-orm/sqlite-core';
import * as authSchema from './auth-schema';

export const profiles = sqliteTable('profiles', {
  id: text('id').primaryKey(),
  email: text('email').notNull(),
  createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull(),
});

export const schema = {
  ...authSchema,
  profiles,
};
