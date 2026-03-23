import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { Client } from 'pg';
import { nanoid } from 'nanoid';
import { createHash } from 'crypto';

const app = new Hono<{ Bindings: { DATABASE_URL: string } }>();

// Rate limiter
const rateLimitMap = new Map();

app.use('*', cors());

// Database middleware
app.use('*', async (c, next) => {
  const client = new Client({ connectionString: c.env.DATABASE_URL });
  await client.connect();

  c.set('db', client);
  await next();

  await client.end();
});

// Authentication middleware
app.use('/v1/*', async (c, next) => {
  const apiKey = c.req.header('x-api-key');
  if (!apiKey) return c.json({ error: 'Missing API key' }, 401);

  const db = c.get('db') as any;
  try {
    const result = await db.query(
      'SELECT * FROM api_keys WHERE public_key = $1 AND is_active = true',
      [apiKey]
    );
    if (result.rows.length === 0) {
      return c.json({ error: 'Invalid API key' }, 401);
    }
    c.set('apiKey', result.rows[0]);
    await next();
  } catch (err) {
    console.error('Auth error:', err);
    return c.json({ error: 'Authentication failed' }, 500);
  }
});

// Health endpoint
app.get('/health', (c) => {
  return c.json({ status: 'ok', version: '1.0.0', edge: true });
});

// Fingerprint endpoint
app.post('/v1/fingerprint', async (c) => {
  const startTime = Date.now();
  
  try {
    const signals = await c.req.json() as any;
    const apiKey = c.get('apiKey');
    const apiKeyId = apiKey.id;
    const clientIp = c.req.header('CF-Connecting-IP') || '0.0.0.0';
    const db = c.get('db') as any;

    // Simple hash function
    const hashSignal = (signal: any): string => {
      return createHash('sha256').update(JSON.stringify(signal)).digest('hex');
    };

    // Hash signals
    const hashes = {
      composite: hashSignal(signals),
      canvas: hashSignal(signals.canvas || ''),
      webgl: hashSignal(signals.webgl || ''),
      audio: hashSignal(signals.audio || ''),
      screen: hashSignal(signals.screen || ''),
      fonts: hashSignal(signals.fonts || ''),
      browser: hashSignal(signals.browser || ''),
      hardware: hashSignal(signals.hardware || ''),
    };

    // Check if visitor exists
    let visitorId: string;
    let isNew = true;
    const matchResult = await db.query(
      'SELECT visitor_id FROM fingerprints WHERE raw_hash = $1 AND api_key_id = $2 LIMIT 1',
      [hashes.composite, apiKeyId]
    );

    if (matchResult.rows.length > 0) {
      visitorId = matchResult.rows[0].visitor_id;
      isNew = false;

      // Update existing
      await db.query(
        `UPDATE fingerprints
         SET last_seen = NOW(), visit_count = visit_count + 1,
             ip_address = $1
         WHERE visitor_id = $2 AND api_key_id = $3`,
        [clientIp, visitorId, apiKeyId]
      );
    } else {
      // Create new visitor
      visitorId = `dvc_${nanoid(16)}`;
      await db.query(
        `INSERT INTO fingerprints
          (visitor_id, raw_hash, canvas_hash, webgl_hash, audio_hash,
           screen_hash, font_hash, browser_hash, hardware_hash,
           ip_address, is_vpn, is_incognito, headless_score, bot_score, api_key_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
        [
          visitorId, hashes.composite, hashes.canvas, hashes.webgl, hashes.audio,
          hashes.screen, hashes.fonts, hashes.browser, hashes.hardware,
          clientIp,
          (signals.evasion?.webrtcIPs?.length || 0) > 0,
          signals.evasion?.isPrivate || false,
          signals.evasion?.headlessScore || 0,
          Object.values(signals.evasion?.bot || {}).filter(Boolean).length,
          apiKeyId,
        ]
      );
    }

    // Get linked devices
    const linkedResult = await db.query(
      `SELECT visitor_id_a, visitor_id_b, link_type, confidence, created_at
       FROM device_links
       WHERE (visitor_id_a = $1 OR visitor_id_b = $1) AND api_key_id = $2`,
      [visitorId, apiKeyId]
    );

    // Calculate risk score
    let riskScore = 0;
    if (isNew) riskScore += 20;
    if ((signals.evasion?.webrtcIPs?.length || 0) > 0) riskScore += 30;
    if (signals.evasion?.isPrivate) riskScore += 25;
    if (signals.evasion?.headlessScore > 0.5) riskScore += 35;
    if (Object.values(signals.evasion?.bot || {}).filter(Boolean).length > 0) riskScore += 40;
    if (linkedResult.rows.length > 3) riskScore += 15;
    riskScore = Math.min(100, Math.max(0, riskScore));

    const processingTime = Date.now() - startTime;

    return c.json({
      visitorId,
      isNew,
      confidence: isNew ? 1.0 : 0.95,
      riskScore,
      linkedDevices: linkedResult.rows.map(d => ({
        visitorIdA: d.visitor_id_a,
        visitorIdB: d.visitor_id_b,
        linkType: d.link_type,
        confidence: d.confidence,
        linkedAt: d.created_at,
      })),
      processingTimeMs: processingTime,
    });
  } catch (err: any) {
    console.error('Fingerprint error:', err);
    return c.json({ error: 'Failed to process fingerprint', details: err.message }, 500);
  }
});

// Ready endpoint
app.get('/ready', (c) => {
  return c.json({ ready: true });
});

export default app;
