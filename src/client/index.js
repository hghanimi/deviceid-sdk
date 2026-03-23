const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const crypto = require('crypto');
const { nanoid } = require('nanoid');
 
const SignalHasher = require('./services/hasher');
const FuzzyMatcher = require('./services/matcher');
const IdentityGraph = require('./services/graph');
 
// ═══════════════════════════════════════════
// DATABASE
// ═══════════════════════════════════════════
 
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://localhost:5432/deviceid',
  max: 20,
});
 
const db = {
  query: (text, params) => pool.query(text, params),
};
 
const matcher = new FuzzyMatcher(db);
const graph = new IdentityGraph(db);
 
// ═══════════════════════════════════════════
// MIDDLEWARE
// ═══════════════════════════════════════════
 
async function authenticate(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey) return res.status(401).json({ error: 'Missing API key' });
 
  try {
    const result = await db.query(
      'SELECT * FROM api_keys WHERE public_key = $1 AND is_active = true',
      [apiKey]
    );
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid API key' });
    }
    req.apiKey = result.rows[0];
    next();
  } catch (err) {
    console.error('Auth error:', err);
    res.status(500).json({ error: 'Authentication failed' });
  }
}
 
// Simple in-memory rate limiter (use Redis in production)
const rateLimitMap = new Map();
 
function rateLimit(req, res, next) {
  const key = req.apiKey.id;
  const now = Date.now();
  const windowMs = 60000; // 1 minute
  const limit = req.apiKey.rate_limit || 1000;
 
  if (!rateLimitMap.has(key)) {
    rateLimitMap.set(key, { count: 1, resetAt: now + windowMs });
    return next();
  }
 
  const entry = rateLimitMap.get(key);
  if (now > entry.resetAt) {
    entry.count = 1;
    entry.resetAt = now + windowMs;
    return next();
  }
 
  entry.count++;
  if (entry.count > limit) {
    return res.status(429).json({
      error: 'Rate limit exceeded',
      retryAfter: Math.ceil((entry.resetAt - now) / 1000),
    });
  }
 
  next();
}
 
// ═══════════════════════════════════════════
// APP
// ═══════════════════════════════════════════
 
const app = express();
 
app.use(cors());
app.use(express.json({ limit: '256kb' }));
 
// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', version: '1.0.0' });
});
 
// ═══════════════════════════════════════════
// MAIN ENDPOINT: POST /v1/fingerprint
// ═══════════════════════════════════════════
 
app.post('/v1/fingerprint', authenticate, rateLimit, async (req, res) => {
  const startTime = Date.now();
 
  try {
    const signals = req.body;
    const apiKeyId = req.apiKey.id;
 
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
        req.ip,
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
      `, [hashes.composite, req.ip, visitorId, apiKeyId]);
 
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
 
    // 4. Risk signals
    const riskSignals = {
      vpn: (signals.evasion?.webrtcIPs?.length || 0) > 0
           && signals.evasion?.webrtcIPs?.[0] !== req.ip,
      incognito: signals.evasion?.isPrivate || false,
      headless: (signals.evasion?.headlessScore || 0) >= 3,
      bot: Object.values(signals.evasion?.bot || {}).filter(Boolean).length >= 2,
      multiAccount: linkedDevices.length > 1,
      velocityAnomaly: false,
    };
 
    // 5. Fire webhooks (async)
    if (matchResult.isNew || riskSignals.bot || riskSignals.multiAccount) {
      process.nextTick(() => {
        graph.fireWebhooks(apiKeyId, {
          event: matchResult.isNew ? 'new_device' : 'risk_detected',
          visitorId,
          riskSignals,
        }).catch(err => console.error('Webhook error:', err));
      });
    }
 
    // 6. Log event
    await db.query(`
      INSERT INTO events (visitor_id, event_type, event_data, ip_address, api_key_id)
      VALUES ($1, $2, $3, $4, $5)
    `, [
      visitorId,
      matchResult.isNew ? 'new_device' : 'returning_device',
      JSON.stringify({ confidence: matchResult.confidence, matchType: matchResult.matchType, riskSignals }),
      req.ip,
      apiKeyId,
    ]);
 
    // Response
    res.json({
      visitorId,
      confidence: matchResult.confidence || 1.0,
      isNewDevice: matchResult.isNew,
      linkedDevices: linkedDevices.length,
      riskSignals,
      requestId: `req_${nanoid(12)}`,
      processingTime: Date.now() - startTime,
    });
 
  } catch (err) {
    console.error('Fingerprint error:', err);
    res.status(500).json({ error: 'Internal error', requestId: `req_${nanoid(12)}` });
  }
});
 
// ═══════════════════════════════════════════
// VISITOR LOOKUP
// ═══════════════════════════════════════════
 
app.get('/v1/visitor/:visitorId', authenticate, async (req, res) => {
  const { visitorId } = req.params;
  const apiKeyId = req.apiKey.id;
 
  const fp = await db.query(
    'SELECT * FROM fingerprints WHERE visitor_id = $1 AND api_key_id = $2',
    [visitorId, apiKeyId]
  );
 
  if (fp.rows.length === 0) {
    return res.status(404).json({ error: 'Visitor not found' });
  }
 
  const events = await db.query(
    'SELECT * FROM events WHERE visitor_id = $1 AND api_key_id = $2 ORDER BY created_at DESC LIMIT 50',
    [visitorId, apiKeyId]
  );
 
  const linked = await graph.getLinkedDevices(visitorId, apiKeyId);
 
  res.json({
    visitor: fp.rows[0],
    recentEvents: events.rows,
    linkedDevices: linked,
  });
});
 
// ═══════════════════════════════════════════
// START
// ═══════════════════════════════════════════
 
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`DeviceID API running on port ${PORT}`);
});
 
module.exports = app;