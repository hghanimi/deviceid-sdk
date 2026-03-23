import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { Client } from 'pg';
import { nanoid } from 'nanoid';

// Assuming you have adapted these to be edge-compatible (no Node-specific APIs)
import SignalHasher from '../server/services/Hasher';
import FuzzyMatcher from '../server/services/matcher';
import IdentityGraph from '../server/services/graph';

const app = new Hono();

// ═══════════════════════════════════════════
// GLOBAL STATE & MIDDLEWARE
// ═══════════════════════════════════════════

// Note: In Workers, memory is per-isolate (edge node). 
// This rate limiter will limit per datacenter, not globally. 
// For a true global rate limit, use Cloudflare Rate Limiting rules or Durable Objects.
const rateLimitMap = new Map();

app.use('*', cors());

// Inject DB and Services into the request context
app.use('*', async (c, next) => {
  // Use Cloudflare Hyperdrive connection string mapped to env.DATABASE_URL
  const client = new Client({ connectionString: c.env.DATABASE_URL });
  await client.connect();

  const db = {
    query: (text, params) => client.query(text, params),
  };

  c.set('db', db);
  c.set('matcher', new FuzzyMatcher(db));
  c.set('graph', new IdentityGraph(db));

  await next();

  // Clean up DB connection after response is sent
  c.executionCtx.waitUntil(client.end());
});

// Authentication Middleware
async function authenticate(c, next) {
  const apiKey = c.req.header('x-api-key');
  if (!apiKey) return c.json({ error: 'Missing API key' }, 401);

  const db = c.get('db');
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
}

// Rate Limiting Middleware
async function rateLimit(c, next) {
  const apiKey = c.get('apiKey');
  const key = apiKey.id;
  const now = Date.now();
  const windowMs = 60000; // 1 minute
  const limit = apiKey.rate_limit || 1000;

  if (!rateLimitMap.has(key)) {
    rateLimitMap.set(key, { count: 1, resetAt: now + windowMs });
    return await next();
  }

  const entry = rateLimitMap.get(key);
  if (now > entry.resetAt) {
    entry.count = 1;
    entry.resetAt = now + windowMs;
    return await next();
  }

  entry.count++;
  if (entry.count > limit) {
    c.header('Retry-After', Math.ceil((entry.resetAt - now) / 1000).toString());
    return c.json({
      error: 'Rate limit exceeded',
      retryAfter: Math.ceil((entry.resetAt - now) / 1000),
    }, 429);
  }

  await next();
}

// ═══════════════════════════════════════════
// ROUTES
// ═══════════════════════════════════════════

app.get('/health', (c) => {
  return c.json({ status: 'ok', version: '1.0.0', edge: true });
});

app.post('/v1/fingerprint', authenticate, rateLimit, async (c) => {
  const startTime = Date.now();
  
  try {
    const signals = await c.req.json();
    const apiKey = c.get('apiKey');
    const apiKeyId = apiKey.id;
    const clientIp = c.req.header('CF-Connecting-IP') || '0.0.0.0';
    
    const db = c.get('db');
    const matcher = c.get('matcher');
    const graph = c.get('graph');

    // 1. Hash signals
    const hashes = SignalHasher.hashSignals(signals);

    // 2. Find or create visitor
    const matchResult = await matcher.findMatch(hashes, signals.storedIds, apiKeyId);
    let visitorId;

    if (matchResult.isNew) {
      visitorId = `dvc_${nanoid(16)}`;

      await db.query(`
        INSERT INTO fingerprints
          (visitor_id, raw_hash, canvas_hash, webgl_hash, audio_hash,
           screen_hash, font_hash, browser_hash, hardware_hash,
           ip_address, is_vpn, is_incognito, headless_score, bot_score, api_key_id)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
      `, [
        visitorId, hashes.composite,
        hashes.canvas, hashes.webgl, hashes.audio,
        hashes.screen, hashes.fonts, hashes.browser, hashes.hardware,
        clientIp,
        (signals.evasion?.webrtcIPs?.length || 0) > 0,
        signals.evasion?.isPrivate || false,
        signals.evasion?.headlessScore || 0,
        Object.values(signals.evasion?.bot || {}).filter(Boolean).length,
        apiKeyId,
      ]);
    } else {
      visitorId = matchResult.visitorId;

      await db.query(`
        UPDATE fingerprints
        SET last_seen = NOW(), visit_count = visit_count + 1,
            raw_hash = $1, ip_address = $2
        WHERE visitor_id = $3 AND api_key_id = $4
      `, [hashes.composite, clientIp, visitorId, apiKeyId]);

      // Cross-browser linking
      if (matchResult.matchType === 'fuzzy' && matchResult.matchedSignals) {
        const crossBrowser = !matchResult.matchedSignals.includes('browser')
          && matchResult.matchedSignals.includes('canvas')
          && matchResult.matchedSignals.includes('webgl');

        if (crossBrowser && matchResult.originalVisitorId) {
          await graph.linkDevices(
            visitorId, matchResult.originalVisitorId,
            'cross_browser', matchResult.confidence,
            { matchedSignals: matchResult.matchedSignals },
            apiKeyId
          );
        }
      }
    }

    // 3. Check linked devices
    const linkedDevices = await graph.getLinkedDevices(visitorId, apiKeyId);

    // 4. Calculate risk score
    const riskScore = calculateRiskScore({
      isNew: matchResult.isNew,
      isVpn: (signals.evasion?.webrtcIPs?.length || 0) > 0,
      isIncognito: signals.evasion?.isPrivate || false,
      headlessScore: signals.evasion?.headlessScore || 0,
      botScore: Object.values(signals.evasion?.bot || {}).filter(Boolean).length,
      deviceCount: linkedDevices.length,
      matchConfidence: matchResult.confidence || 0,
    });

    const processingTime = Date.now() - startTime;

    return c.json({
      visitorId,
      isNew: matchResult.isNew,
      confidence: matchResult.confidence || 1.0,
      riskScore,
      linkedDevices: linkedDevices.map(d => ({
        visitorId: d.visitor_id,
        linkType: d.link_type,
        confidence: d.confidence,
        linkedAt: d.linked_at,
      })),
      processingTimeMs: processingTime,
    }, 200);
  } catch (err) {
    console.error('Fingerprint error:', err);
    return c.json({ error: 'Failed to process fingerprint', details: err.message }, 500);
  }
});

// Helper function to calculate risk score
function calculateRiskScore(factors) {
  let score = 0;
  if (factors.isNew) score += 20;
  if (factors.isVpn) score += 30;
  if (factors.isIncognito) score += 25;
  if (factors.headlessScore > 0.5) score += 35;
  if (factors.botScore > 0) score += 40;
  if (factors.deviceCount > 3) score += 15;
  
  return Math.min(100, score);
}

// Health check for readiness
app.get('/ready', (c) => {
  return c.json({ ready: true });
});

// Export for Cloudflare Worker entry point
export default app;