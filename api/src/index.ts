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

    const hashSignal = (signal: any): string => {
      return createHash('sha256').update(JSON.stringify(signal)).digest('hex');
    };

    const { storedIds, behavior, ...stableSignals } = signals;
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

    const persistFingerprint = async (resolvedVisitorId: string) => {
      await db.query(
        `INSERT INTO fingerprints
          (visitor_id, raw_hash, canvas_hash, webgl_hash, audio_hash,
           screen_hash, font_hash, browser_hash, hardware_hash,
           ip_address, is_vpn, is_incognito, headless_score, bot_score, api_key_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
         ON CONFLICT (raw_hash, api_key_id)
         DO UPDATE SET
           last_seen = NOW(),
           visit_count = fingerprints.visit_count + 1,
           ip_address = EXCLUDED.ip_address,
           is_vpn = EXCLUDED.is_vpn,
           is_incognito = EXCLUDED.is_incognito,
           headless_score = EXCLUDED.headless_score,
           bot_score = EXCLUDED.bot_score`,
        [
          resolvedVisitorId, hashes.composite, hashes.canvas, hashes.webgl, hashes.audio,
          hashes.screen, hashes.fonts, hashes.browser, hashes.hardware,
          clientIp,
          (signals.evasion?.webrtcIPs?.length || 0) > 0,
          signals.evasion?.isPrivate || false,
          Math.round((signals.evasion?.headlessScore || 0) * 100),
          Object.values(signals.evasion?.bot || {}).filter(Boolean).length,
          apiKeyId,
        ]
      );
    };

    const computeBehaviorRisk = (profile: any) => {
      if (!profile) return 0;
      let score = 0;
      if (profile.durationMs < 1500 && profile.totalEvents === 0) score += 15;
      if (profile.totalEvents > 0 && profile.mouseMoves === 0 && profile.touches === 0 && profile.clicks > 0) score += 10;
      if (profile.keys > 3 && profile.averageKeyIntervalMs > 0 && profile.averageKeyIntervalMs < 45) score += 10;
      if (profile.clicks > 2 && profile.averageClickIntervalMs > 0 && profile.averageClickIntervalMs < 120) score += 8;
      if (profile.visibilityState === 'hidden') score += 6;
      if (!profile.hasFocus) score += 4;
      return Math.min(30, score);
    };

    const scoreCandidate = (candidate: any) => {
      const weights = {
        screen: 0.24,
        fonts: 0.22,
        hardware: 0.22,
        webgl: 0.10,
        canvas: 0.08,
        browser: 0.08,
        audio: 0.06,
      };

      let score = 0;
      let stableMatches = 0;
      if (candidate.screen_hash === hashes.screen) { score += weights.screen; stableMatches += 1; }
      if (candidate.font_hash === hashes.fonts) { score += weights.fonts; stableMatches += 1; }
      if (candidate.hardware_hash === hashes.hardware) { score += weights.hardware; stableMatches += 1; }
      if (candidate.webgl_hash === hashes.webgl) score += weights.webgl;
      if (candidate.canvas_hash === hashes.canvas) score += weights.canvas;
      if (candidate.browser_hash === hashes.browser) score += weights.browser;
      if (candidate.audio_hash === hashes.audio) score += weights.audio;

      if (stableMatches === 3) score += 0.08;
      if (stableMatches >= 2 && candidate.ip_address === clientIp) score += 0.04;

      return {
        visitorId: candidate.visitor_id,
        score: Number(Math.min(0.99, score).toFixed(2)),
        stableMatches,
      };
    };

    let visitorId: string;
    let isNew = true;
    let matchConfidence = 1.0;
    let matchMethod = 'new-device';

    const storedVisitorIds = [storedIds?.localStorage, storedIds?.sessionStorage].filter(Boolean);
    if (storedVisitorIds.length > 0) {
      const storedMatch = await db.query(
        `SELECT visitor_id
         FROM fingerprints
         WHERE visitor_id = ANY($1) AND api_key_id = $2
         ORDER BY last_seen DESC
         LIMIT 1`,
        [storedVisitorIds, apiKeyId]
      );

      if (storedMatch.rows.length > 0) {
        visitorId = storedMatch.rows[0].visitor_id;
        isNew = false;
        matchConfidence = 0.99;
        matchMethod = 'stored-id';
        await persistFingerprint(visitorId);
      }
    }

    if (!visitorId) {
      const exactMatch = await db.query(
        'SELECT visitor_id FROM fingerprints WHERE raw_hash = $1 AND api_key_id = $2 LIMIT 1',
        [hashes.composite, apiKeyId]
      );

      if (exactMatch.rows.length > 0) {
        visitorId = exactMatch.rows[0].visitor_id;
        isNew = false;
        matchConfidence = 1.0;
        matchMethod = 'exact';
        await persistFingerprint(visitorId);
      }
    }

    if (!visitorId) {
      const candidates = await db.query(
        `SELECT visitor_id, ip_address, screen_hash, font_hash, hardware_hash,
                webgl_hash, canvas_hash, browser_hash, audio_hash, last_seen
         FROM fingerprints
         WHERE api_key_id = $1
         ORDER BY last_seen DESC
         LIMIT 250`,
        [apiKeyId]
      );

      const scored = candidates.rows
        .map((row: any) => scoreCandidate(row))
        .filter((candidate: any) => candidate.stableMatches >= 2 && candidate.score >= 0.60)
        .sort((left: any, right: any) => right.score - left.score);

      if (scored.length > 0) {
        visitorId = scored[0].visitorId;
        isNew = false;
        matchConfidence = scored[0].score;
        matchMethod = 'weighted';
        await persistFingerprint(visitorId);
      }
    }

    if (!visitorId) {
      visitorId = `dvc_${nanoid(16)}`;
      matchConfidence = 1.0;
      matchMethod = 'new-device';
      await persistFingerprint(visitorId);
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
    const behaviorRisk = computeBehaviorRisk(behavior);
    if (isNew) riskScore += 20;
    if ((signals.evasion?.webrtcIPs?.length || 0) > 0) riskScore += 30;
    if (signals.evasion?.isPrivate) riskScore += 25;
    if (signals.evasion?.headlessScore > 0.5) riskScore += 35;
    if (Object.values(signals.evasion?.bot || {}).filter(Boolean).length > 0) riskScore += 40;
    if (linkedResult.rows.length > 3) riskScore += 15;
    riskScore += behaviorRisk;
    riskScore = Math.min(100, Math.max(0, riskScore));

    const processingTime = Date.now() - startTime;

    return c.json({
      visitorId,
      isNew,
      confidence: isNew ? 1.0 : matchConfidence,
      matchMethod,
      behaviorRisk,
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
