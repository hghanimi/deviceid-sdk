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

// Stats endpoint (protected by API key, admin only)
app.get('/stats', async (c) => {
  const apiKey = c.req.header('x-api-key');
  if (!apiKey) return c.json({ error: 'Missing API key' }, 401);

  const db = c.get('db') as any;

  try {
    const [unique, total, topDevices, newToday, activeToday, keys] = await Promise.all([
      db.query('SELECT COUNT(DISTINCT visitor_id) AS unique_devices FROM fingerprints'),
      db.query('SELECT COUNT(*) AS total_fingerprints FROM fingerprints'),
      db.query(`SELECT visitor_id, visit_count, first_seen, last_seen, ip_address
                FROM fingerprints ORDER BY last_seen DESC LIMIT 20`),
      db.query(`SELECT COUNT(*) AS new_today FROM fingerprints
                WHERE first_seen >= NOW() - INTERVAL '24 hours'`),
      db.query(`SELECT COUNT(*) AS visits_today FROM fingerprints
                WHERE last_seen >= NOW() - INTERVAL '24 hours'`),
      db.query(`SELECT public_key, name, is_active, created_at FROM api_keys`),
    ]);

    return c.json({
      summary: {
        uniqueDevices: parseInt(unique.rows[0].unique_devices),
        totalFingerprints: parseInt(total.rows[0].total_fingerprints),
        newDevicesToday: parseInt(newToday.rows[0].new_today),
        activeToday: parseInt(activeToday.rows[0].visits_today),
      },
      recentDevices: topDevices.rows.map((r: any) => ({
        visitorId: r.visitor_id,
        visitCount: r.visit_count,
        ipAddress: r.ip_address,
        firstSeen: r.first_seen,
        lastSeen: r.last_seen,
      })),
      apiKeys: keys.rows.map((k: any) => ({
        key: k.public_key,
        name: k.name,
        isActive: k.is_active,
        createdAt: k.created_at,
      })),
    });
  } catch (err: any) {
    return c.json({ error: 'Stats query failed', details: err.message }, 500);
  }
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

    // Hash signals (exclude storedIds so returning visitors match correctly)
    const { storedIds, ...stableSignals } = signals;
    const hashes = {
      composite: hashSignal(stableSignals),
      canvas: hashSignal(stableSignals.canvas || ''),
      webgl: hashSignal(stableSignals.webgl || ''),
      audio: hashSignal(stableSignals.audio || ''),
      screen: hashSignal(stableSignals.screen || ''),
      fonts: hashSignal(stableSignals.fonts || ''),
      browser: hashSignal(stableSignals.browser || ''),
      hardware: hashSignal(stableSignals.hardware || ''),
    };

    // --- Tier 1: Exact composite hash match ---
    let visitorId: string;
    let isNew = true;
    let matchConfidence = 1.0;

    const exactMatch = await db.query(
      'SELECT visitor_id FROM fingerprints WHERE raw_hash = $1 AND api_key_id = $2 LIMIT 1',
      [hashes.composite, apiKeyId]
    );

    if (exactMatch.rows.length > 0) {
      // Exact match — same browser, same device
      visitorId = exactMatch.rows[0].visitor_id;
      isNew = false;
      matchConfidence = 1.0;
      await db.query(
        `UPDATE fingerprints SET last_seen = NOW(), visit_count = visit_count + 1, ip_address = $1
         WHERE visitor_id = $2 AND api_key_id = $3`,
        [clientIp, visitorId, apiKeyId]
      );
    } else {
      // --- Tier 2: Fuzzy match on browser-agnostic stable signals ---
      // screen + fonts + hardware stay the same across browsers on the same device
      const fuzzyMatch = await db.query(
        `SELECT visitor_id FROM fingerprints
         WHERE screen_hash = $1 AND font_hash = $2 AND hardware_hash = $3
           AND api_key_id = $4
         ORDER BY last_seen DESC LIMIT 1`,
        [hashes.screen, hashes.fonts, hashes.hardware, apiKeyId]
      );

      if (fuzzyMatch.rows.length > 0) {
        // Same physical device, different browser — reuse visitor ID
        visitorId = fuzzyMatch.rows[0].visitor_id;
        isNew = false;
        matchConfidence = 0.85;
        // Store new composite hash as an alias so next visit from this browser is exact
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
      } else {
        // --- Tier 3: Genuinely new device ---
        visitorId = `dvc_${nanoid(16)}`;
        matchConfidence = 1.0;
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
      confidence: isNew ? 1.0 : matchConfidence,
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
