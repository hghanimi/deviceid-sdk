import { Hono } from 'hono';
import { nanoid } from 'nanoid';
import { AppEnv } from '../types';

const router = new Hono<AppEnv>();

async function hashPassword(password: string): Promise<string> {
  const salt = nanoid(16);
  const data = new TextEncoder().encode(salt + password);
  const hashBuf = await crypto.subtle.digest('SHA-256', data);
  const hashHex = [...new Uint8Array(hashBuf)].map(b => b.toString(16).padStart(2, '0')).join('');
  return `${salt}:${hashHex}`;
}

async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [salt, hash] = stored.split(':');
  if (!salt || !hash) return false;
  const data = new TextEncoder().encode(salt + password);
  const hashBuf = await crypto.subtle.digest('SHA-256', data);
  const hashHex = [...new Uint8Array(hashBuf)].map(b => b.toString(16).padStart(2, '0')).join('');
  return hashHex === hash;
}

// POST /v1/auth/register — Create a user account (requires valid API key)
router.post('/v1/auth/register', async (c) => {
  const db = c.get('db') as any;
  const apiKey = c.get('apiKey') as any;
  try {
    const body = await c.req.json() as any;
    const { username, password, displayName } = body;
    if (!username || !password) return c.json({ error: 'username and password required' }, 400);
    if (password.length < 4) return c.json({ error: 'Password must be at least 4 characters' }, 400);
    if (!/^[a-zA-Z0-9_]+$/.test(username)) return c.json({ error: 'Username must be alphanumeric' }, 400);
    const existing = await db.query('SELECT id FROM users WHERE username = $1', [username.toLowerCase()]);
    if (existing.rows.length > 0) return c.json({ error: 'Username already taken' }, 409);
    const passwordHash = await hashPassword(password);
    const result = await db.query(
      `INSERT INTO users (api_key_id, username, password_hash, display_name, role)
       VALUES ($1, $2, $3, $4, 'operator')
       RETURNING id, username, display_name, role, created_at`,
      [apiKey.id, username.toLowerCase(), passwordHash, displayName || username]
    );
    return c.json({ user: result.rows[0] }, 201);
  } catch (err: any) {
    return c.json({ error: 'Registration failed', details: err.message }, 500);
  }
});

// POST /v1/auth/login — Login with username+password, returns user + API key
router.post('/v1/auth/login', async (c) => {
  const db = c.get('db') as any;
  try {
    const body = await c.req.json() as any;
    const { username, password } = body;
    if (!username || !password) return c.json({ error: 'username and password required' }, 400);
    const result = await db.query(
      `SELECT u.*, ak.public_key, ak.name AS key_name, ak.is_active AS key_active
       FROM users u JOIN api_keys ak ON ak.id = u.api_key_id
       WHERE u.username = $1 AND u.is_active = true`,
      [username.toLowerCase()]
    );
    if (result.rows.length === 0) return c.json({ error: 'Invalid credentials' }, 401);
    const user = result.rows[0];
    if (!user.key_active) return c.json({ error: 'Account disabled' }, 403);
    const valid = await verifyPassword(password, user.password_hash);
    if (!valid) return c.json({ error: 'Invalid credentials' }, 401);
    await db.query('UPDATE users SET last_login = NOW() WHERE id = $1', [user.id]);
    return c.json({
      user: { id: user.id, username: user.username, displayName: user.display_name, role: user.role },
      apiKey: user.public_key,
      keyName: user.key_name,
    });
  } catch (err: any) {
    return c.json({ error: 'Login failed', details: err.message }, 500);
  }
});

// POST /v1/admin/reset-db — Clear all compliance data (fresh start)
router.post('/v1/admin/reset-db', async (c) => {
  const db = c.get('db') as any;
  const apiKey = c.get('apiKey') as any;
  const clientIp = c.req.header('CF-Connecting-IP') || '0.0.0.0';
  try {
    const tables = [
      'compliance_audit_log',
      'screening_results',
      'merchant_alerts',
      'merchant_documents',
      'merchant_owners',
      'merchants',
      'users',
    ];
    for (const table of tables) {
      try {
        await db.query(`TRUNCATE TABLE ${table} CASCADE`);
      } catch (e: any) {
        if (!String(e?.message || '').toLowerCase().includes('does not exist')) throw e;
      }
    }
    await db.query(
      `INSERT INTO compliance_audit_log (action, actor, details, ip_address)
       VALUES ('database_reset', $1, '{"reason":"fresh_start"}'::jsonb, $2)`,
      [apiKey.public_key, clientIp]
    );
    return c.json({ message: 'Database cleared successfully.' });
  } catch (err: any) {
    return c.json({ error: 'Failed to reset database', details: err.message }, 500);
  }
});

export default router;
