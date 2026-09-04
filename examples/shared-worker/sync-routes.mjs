import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

// Keep relative imports local to each worker's auth/database configuration.
const source = readFileSync(new URL('./routes/app.ts', import.meta.url), 'utf8');
const destination = resolve('src/routes/app.generated.ts');
const generated = '// Generated from examples/shared-worker/routes/app.ts. Do not edit.\n' + source;
let current;
try { current = readFileSync(destination, 'utf8'); } catch (error) {
  if (error.code !== 'ENOENT') throw error;
}
if (current !== generated) writeFileSync(destination, generated);
