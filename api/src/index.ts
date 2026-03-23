import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { Client } from 'pg';
import { nanoid } from 'nanoid';
import { createHash } from 'crypto';

const app = new Hono<{ Bindings: { DATABASE_URL: string } }>();

const normalizeIp = (ip?: string | null): string => {
  if (!ip) return '';
  return ip.trim().toLowerCase().replace(/^::ffff:/, '');
};

const isPrivateIp = (ip?: string | null): boolean => {
  const value = normalizeIp(ip);
  if (!value) return true;

  if (value === '127.0.0.1' || value === '0.0.0.0') return true;
  if (value.startsWith('10.')) return true;
  if (value.startsWith('192.168.')) return true;
  if (value.startsWith('169.254.')) return true;
  if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(value)) return true;

  if (value === '::1') return true;
  if (value.startsWith('fc') || value.startsWith('fd')) return true;
  if (value.startsWith('fe80:')) return true;

  return false;
};

app.use('*', cors());

app.use('*', async (c, next) => {
  const client = new Client({ connectionString: c.env.DATABASE_URL });
  await client.connect();
  c.set('db', client);
  await next();
  await client.end();
});

app.use('/v1/*', async (c, next) => {
  const apiKey = c.req.header('x-api-key');
  if (!apiKey) return c.json({ error: 'Missing API key' }, 401);
  const db = c.get('db') as any;
  try {
    const result = await db.query(
      'SELECT * FROM api_keys WHERE public_key = $1 AND is_active = true',
      [apiKey]
    );
    if (result.rows.length === 0) return c.json({ error: 'Invalid API key' }, 401);
    c.set('apiKey', result.rows[0]);
    await next();
  } catch (err) {
    return c.json({ error: 'Authentication failed' }, 500);
  }
});

app.get('/health', (c) => c.json({ status: 'ok', version: '2.0.0', edge: true }));

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
        visitorId: r.visitor_id, visitCount: r.visit_count,
        ipAddress: r.ip_address, firstSeen: r.first_seen, lastSeen: r.last_seen,
      })),
      apiKeys: keys.rows.map((k: any) => ({
        key: k.public_key, name: k.name, isActive: k.is_active, createdAt: k.created_at,
      })),
    });
  } catch (err: any) {
    return c.json({ error: 'Stats query failed', details: err.message }, 500);
  }
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// FINGERPRINT ENDPOINT — v2 with weighted matching
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
app.post('/v1/fingerprint', async (c) => {
  const startTime = Date.now();

  try {
    const signals = await c.req.json() as any;
    const apiKey = c.get('apiKey') as any;
    const apiKeyId = apiKey.id;
    const clientIp = c.req.header('CF-Connecting-IP') || '0.0.0.0';
    const db = c.get('db') as any;

    // Hash helper
    const h = (signal: any): string => {
      if (signal === null || signal === undefined) return '';
      return createHash('sha256').update(JSON.stringify(signal)).digest('hex');
    };

    // Build stable composite — exclude volatile/session-specific fields
    const { storedIds, ts, collectionMs, v, evasion, ...stableCore } = signals;

    const hashes = {
      composite: h(stableCore),
      canvas:    h(signals.canvas),
      webgl:     h(signals.webgl),
      audio:     h(signals.audio),
      screen:    h(signals.screen),
      fonts:     h(signals.fonts),
      browser:   h(signals.browser),
      hardware:  h(signals.hardware),
    };

    // headlessScore is a 0-1 float; cast to 0-100 integer for the INTEGER DB column
    const headlessScoreInt = Math.round((evasion?.headlessScore || 0) * 100);
    const botCount = Object.values(evasion?.bot || {}).filter(Boolean).length;
    const normalizedClientIp = normalizeIp(clientIp);
    const webrtcIps: string[] = Array.isArray(evasion?.webrtcIPs)
      ? evasion.webrtcIPs.map((ip: string) => normalizeIp(ip)).filter(Boolean)
      : [];
    const publicWebrtcIps = webrtcIps.filter((ip) => !isPrivateIp(ip));
    const isVpn = publicWebrtcIps.length > 0
      && (isPrivateIp(normalizedClientIp) || publicWebrtcIps.some((ip) => ip !== normalizedClientIp));

    // ─── Tier 1: Exact composite hash match ───
    let visitorId: string;
    let isNew = true;
    let matchConfidence = 1.0;
    let matchTier = 'new';
    let matchedSignals: string[] = [];

    const exactMatch = await db.query(
      'SELECT visitor_id FROM fingerprints WHERE raw_hash = $1 AND api_key_id = $2 LIMIT 1',
      [hashes.composite, apiKeyId]
    );

    if (exactMatch.rows.length > 0) {
      visitorId = exactMatch.rows[0].visitor_id;
      isNew = false;
      matchConfidence = 1.0;
      matchTier = 'exact';
      await db.query(
        `UPDATE fingerprints SET last_seen = NOW(), visit_count = visit_count + 1, ip_address = $1
         WHERE visitor_id = $2 AND api_key_id = $3`,
        [clientIp, visitorId, apiKeyId]
      );
    } else {
      // ─── Tier 2: Weighted fuzzy match ───
      // Pull candidates sharing at least one strong signal
      const candidates = await db.query(
        `SELECT visitor_id, canvas_hash, webgl_hash, audio_hash,
                screen_hash, font_hash, browser_hash, hardware_hash
         FROM fingerprints
         WHERE api_key_id = $1
           AND (canvas_hash = $2 OR webgl_hash = $3 OR audio_hash = $4
                OR screen_hash = $5 OR hardware_hash = $6)
         ORDER BY last_seen DESC LIMIT 50`,
        [apiKeyId, hashes.canvas, hashes.webgl, hashes.audio,
         hashes.screen, hashes.hardware]
      );

      // Signal weights — ordered by spoofing difficulty
      const weights: Record<string, number> = {
        canvas: 0.22, webgl: 0.18, audio: 0.14,
        screen: 0.12, hardware: 0.12, fonts: 0.10, browser: 0.06,
      };

      let bestScore = 0;
      let bestCandidate: any = null;
      let bestMatched: string[] = [];

      for (const cand of candidates.rows) {
        let score = 0;
        let total = 0;
        const matched: string[] = [];

        const pairs = [
          { key: 'canvas',   a: hashes.canvas,   b: cand.canvas_hash },
          { key: 'webgl',    a: hashes.webgl,    b: cand.webgl_hash },
          { key: 'audio',    a: hashes.audio,    b: cand.audio_hash },
          { key: 'screen',   a: hashes.screen,   b: cand.screen_hash },
          { key: 'hardware', a: hashes.hardware, b: cand.hardware_hash },
          { key: 'fonts',    a: hashes.fonts,    b: cand.font_hash },
          { key: 'browser',  a: hashes.browser,  b: cand.browser_hash },
        ];

        for (const { key, a, b } of pairs) {
          if (!a || !b) continue;
          total += weights[key];
          if (a === b) { score += weights[key]; matched.push(key); }
        }

        const normalized = total > 0 ? score / total : 0;
        if (normalized > bestScore) {
          bestScore = normalized;
          bestCandidate = cand;
          bestMatched = matched;
        }
      }

      const MATCH_THRESHOLD = 0.60;

      if (bestCandidate && bestScore >= MATCH_THRESHOLD) {
        visitorId = bestCandidate.visitor_id;
        isNew = false;
        matchConfidence = Math.round(bestScore * 100) / 100;
        matchTier = 'fuzzy';
        matchedSignals = bestMatched;

        // Store alias so next visit from this browser is exact
        await db.query(
          `INSERT INTO fingerprints
            (visitor_id, raw_hash, canvas_hash, webgl_hash, audio_hash,
             screen_hash, font_hash, browser_hash, hardware_hash,
             ip_address, is_vpn, is_incognito, headless_score, bot_score, api_key_id)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
          [visitorId, hashes.composite, hashes.canvas, hashes.webgl, hashes.audio,
           hashes.screen, hashes.fonts, hashes.browser, hashes.hardware,
           clientIp, isVpn, evasion?.isPrivate || false, headlessScoreInt, botCount,
           apiKeyId]
        );
      } else {
        // ─── Tier 3: New device ───
        visitorId = `dvc_${nanoid(16)}`;
        matchConfidence = 1.0;
        matchTier = 'new';

        await db.query(
          `INSERT INTO fingerprints
            (visitor_id, raw_hash, canvas_hash, webgl_hash, audio_hash,
             screen_hash, font_hash, browser_hash, hardware_hash,
             ip_address, is_vpn, is_incognito, headless_score, bot_score, api_key_id)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
          [visitorId, hashes.composite, hashes.canvas, hashes.webgl, hashes.audio,
           hashes.screen, hashes.fonts, hashes.browser, hashes.hardware,
           clientIp, isVpn, evasion?.isPrivate || false, headlessScoreInt, botCount,
           apiKeyId]
        );
      }
    }

    // ─── Linked devices ───
    const linkedResult = await db.query(
      `SELECT visitor_id_a, visitor_id_b, link_type, confidence, created_at
       FROM device_links
       WHERE (visitor_id_a = $1 OR visitor_id_b = $1) AND api_key_id = $2`,
      [visitorId, apiKeyId]
    );

    // ─── Risk scoring ───
    let riskScore = 0;
    if (isNew) riskScore += 15;
    if (isVpn) riskScore += 25;
    if (evasion?.isPrivate) riskScore += 20;
    if ((evasion?.headlessScore || 0) > 0.4) riskScore += 30;
    if (botCount > 0) riskScore += 35;
    if (linkedResult.rows.length > 3) riskScore += 15;
    const tampering = evasion?.tampering || {};
    if (tampering.canvasOverride) riskScore += 20;
    if (tampering.uaOverride) riskScore += 15;
    if (tampering.navigatorProxy) riskScore += 20;
    if (tampering.genericRenderer) riskScore += 10;
    if (tampering.screenMismatch) riskScore += 15;
    riskScore = Math.min(100, Math.max(0, riskScore));

    return c.json({
      visitorId,
      isNew,
      confidence: isNew ? 1.0 : matchConfidence,
      matchTier,
      matchedSignals: matchedSignals.length > 0 ? matchedSignals : undefined,
      riskScore,
      riskSignals: {
        vpn: isVpn,
        incognito: evasion?.isPrivate || false,
        headless: (evasion?.headlessScore || 0) > 0.4,
        bot: botCount >= 2,
        tampered: !!(tampering.canvasOverride || tampering.uaOverride || tampering.navigatorProxy),
        multiAccount: linkedResult.rows.length > 1,
      },
      linkedDevices: linkedResult.rows.length,
      processingMs: Date.now() - startTime,
      sdkVersion: signals.v || '1.0.0',
    });
  } catch (err: any) {
    console.error('Fingerprint error:', err);
    return c.json({ error: 'Failed to process fingerprint', details: err.message }, 500);
  }
});

app.get('/ready', (c) => c.json({ ready: true }));

export default app;
