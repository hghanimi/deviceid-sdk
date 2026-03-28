import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { AppEnv } from './types';
import { getDb, shouldRetryDbError, resetPool } from './db';
import authRouter from './routes/auth';
import dashboardRouter from './routes/dashboard';
import fingerprintRouter from './routes/fingerprint';
import merchantsRouter from './routes/merchants';
import documentsRouter from './routes/documents';
import complianceRouter from './routes/compliance';
import kycRouter from './routes/kyc';

const app = new Hono<AppEnv>();

const apiKeyCache = new Map<string, any>();

// ─── Global middleware ───
app.use('*', cors());

app.use('*', async (c, next) => {
  const db = getDb(c.env.DATABASE_URL);
  c.set('db', db);
  await next();
});

app.use('/v1/*', async (c, next) => {
  const apiKey = c.req.header('x-api-key');
  if (!apiKey) return c.json({ error: 'Missing API key' }, 401);
  const db = c.get('db') as any;
  try {
    let result;
    try {
      result = await db.query(
        'SELECT * FROM api_keys WHERE public_key = $1 AND is_active = true',
        [apiKey]
      );
    } catch (firstErr) {
      if (!shouldRetryDbError(firstErr)) throw firstErr;
      resetPool();
      const retryDb = getDb(c.env.DATABASE_URL);
      result = await retryDb.query(
        'SELECT * FROM api_keys WHERE public_key = $1 AND is_active = true',
        [apiKey]
      );
      c.set('db', retryDb);
    }
    if (result.rows.length === 0) return c.json({ error: 'Invalid API key' }, 401);
    apiKeyCache.set(apiKey, result.rows[0]);
    c.set('apiKey', result.rows[0]);
    await next();
  } catch (err) {
    const cached = apiKeyCache.get(apiKey);
    if (cached) {
      c.set('apiKey', cached);
      await next();
      return;
    }
    return c.json({ error: 'Authentication failed' }, 500);
  }
});

// ─── Route modules ───
app.route('/', dashboardRouter);
app.route('/', authRouter);
app.route('/', fingerprintRouter);
app.route('/', merchantsRouter);
app.route('/', documentsRouter);
app.route('/', complianceRouter);
app.route('/', kycRouter);

export default app;
