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

app.get('/v1/dashboard', async (c) => {
  const db = c.get('db') as any;
  const apiKey = c.get('apiKey') as any;

  // Restrict portfolio-wide monitoring to Wayl operator keys.
  if (!apiKey?.public_key || !String(apiKey.public_key).startsWith('pk_live_wayl')) {
    return c.json({ error: 'Dashboard access is restricted to Wayl operator keys.' }, 403);
  }

  try {
    const [overview, merchants, riskyEvents, hourly, allEventsQ, linkedCountQ] = await Promise.all([
      db.query(
        `SELECT
           COUNT(*)::int AS events_24h,
           COUNT(DISTINCT visitor_id)::int AS unique_devices_24h,
           COUNT(*) FILTER (WHERE first_seen >= NOW() - INTERVAL '24 hours')::int AS new_devices_24h,
           COUNT(*) FILTER (WHERE is_vpn = true)::int AS vpn_24h,
           COUNT(*) FILTER (WHERE is_incognito = true)::int AS incognito_24h,
           COUNT(*) FILTER (
             WHERE is_vpn = true
                OR is_incognito = true
                OR headless_score >= 40
                OR bot_score >= 2
           )::int AS high_risk_24h,
           ROUND(AVG(
             CASE
               WHEN is_vpn OR is_incognito OR headless_score >= 40 OR bot_score >= 2 THEN 30
               WHEN visit_count > 3 THEN 95
               ELSE 75
             END
           ))::int AS avg_confidence_pct
         FROM fingerprints
         WHERE last_seen >= NOW() - INTERVAL '24 hours'`
      ),
      db.query(
        `SELECT
           k.name,
           k.public_key,
           COUNT(f.*)::int AS events_24h,
           COUNT(DISTINCT f.visitor_id)::int AS unique_devices_24h,
           COUNT(*) FILTER (
             WHERE f.is_vpn = true
                OR f.is_incognito = true
                OR f.headless_score >= 40
                OR f.bot_score >= 2
           )::int AS high_risk_24h
         FROM api_keys k
         LEFT JOIN fingerprints f
           ON f.api_key_id = k.id
          AND f.last_seen >= NOW() - INTERVAL '24 hours'
         WHERE k.is_active = true
         GROUP BY k.name, k.public_key
         ORDER BY events_24h DESC, unique_devices_24h DESC
         LIMIT 100`
      ),
      db.query(
        `SELECT
           f.visitor_id,
           f.last_seen,
           f.ip_address,
           f.is_vpn,
           f.is_incognito,
           f.headless_score,
           f.bot_score,
           f.visit_count,
           k.name AS merchant_name,
           k.public_key
         FROM fingerprints f
         JOIN api_keys k ON k.id = f.api_key_id
         WHERE f.last_seen >= NOW() - INTERVAL '24 hours'
           AND (
             f.is_vpn = true
             OR f.is_incognito = true
             OR f.headless_score >= 40
             OR f.bot_score >= 2
           )
         ORDER BY f.last_seen DESC
         LIMIT 80`
      ),
      db.query(
        `SELECT
           DATE_TRUNC('hour', last_seen) AS hour_bucket,
           COUNT(*)::int AS events,
           COUNT(DISTINCT visitor_id)::int AS unique_devices,
           COUNT(*) FILTER (
             WHERE NOT (is_vpn OR is_incognito OR headless_score >= 40 OR bot_score >= 2)
           )::int AS trusted,
           COUNT(*) FILTER (
             WHERE is_vpn = true OR is_incognito = true OR headless_score >= 40 OR bot_score >= 2
           )::int AS high_risk
         FROM fingerprints
         WHERE last_seen >= NOW() - INTERVAL '24 hours'
         GROUP BY hour_bucket
         ORDER BY hour_bucket ASC`
      ),
      db.query(
        `SELECT
           f.visitor_id,
           f.last_seen,
           f.first_seen,
           f.ip_address,
           f.is_vpn,
           f.is_incognito,
           f.headless_score,
           f.bot_score,
           f.visit_count,
           k.name AS merchant_name,
           k.public_key
         FROM fingerprints f
         JOIN api_keys k ON k.id = f.api_key_id
         WHERE f.last_seen >= NOW() - INTERVAL '24 hours'
         ORDER BY f.last_seen DESC
         LIMIT 200`
      ),
      // Count linked devices per visitor (for identity linking display)
      db.query(
        `SELECT sub.visitor_id, COUNT(*)::int AS link_count
         FROM (
           SELECT visitor_id_a AS visitor_id FROM device_links
           UNION ALL
           SELECT visitor_id_b AS visitor_id FROM device_links
         ) sub
         GROUP BY sub.visitor_id`
      ).catch(() => ({ rows: [] })),
    ]);

    // Build a map of visitor_id → link count
    const linkMap = new Map<string, number>();
    for (const row of linkedCountQ.rows) {
      linkMap.set(row.visitor_id, row.link_count);
    }

    return c.json({
      window: '24h',
      generatedAt: new Date().toISOString(),
      overview: {
        ...(overview.rows[0] || {
          events_24h: 0, unique_devices_24h: 0, new_devices_24h: 0,
          vpn_24h: 0, incognito_24h: 0, high_risk_24h: 0, avg_confidence_pct: 0,
        }),
        linked_identities: linkMap.size,
      },
      merchants: merchants.rows.map((row: any) => ({
        name: row.name,
        publicKey: row.public_key,
        events24h: row.events_24h,
        uniqueDevices24h: row.unique_devices_24h,
        highRisk24h: row.high_risk_24h,
      })),
      riskyEvents: riskyEvents.rows.map((row: any) => ({
        visitorId: row.visitor_id,
        merchantName: row.merchant_name,
        publicKey: row.public_key,
        ipAddress: row.ip_address,
        isVpn: row.is_vpn,
        isIncognito: row.is_incognito,
        headlessScore: row.headless_score,
        botScore: row.bot_score,
        visitCount: row.visit_count,
        lastSeen: row.last_seen,
      })),
      allEvents: allEventsQ.rows.map((row: any) => ({
        visitorId: row.visitor_id,
        merchantName: row.merchant_name,
        publicKey: row.public_key,
        ipAddress: row.ip_address,
        isVpn: row.is_vpn,
        isIncognito: row.is_incognito,
        headlessScore: row.headless_score,
        botScore: row.bot_score,
        visitCount: row.visit_count,
        firstSeen: row.first_seen,
        lastSeen: row.last_seen,
        linkedCount: linkMap.get(row.visitor_id) || 0,
      })),
      hourly: hourly.rows.map((row: any) => ({
        hour: row.hour_bucket,
        events: row.events,
        uniqueDevices: row.unique_devices,
        trusted: row.trusted,
        highRisk: row.high_risk,
      })),
    });
  } catch (err: any) {
    return c.json({ error: 'Dashboard query failed', details: err.message }, 500);
  }
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// VISITOR DETAIL ENDPOINT
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
app.get('/v1/visitor/:id', async (c) => {
  const db = c.get('db') as any;
  const apiKey = c.get('apiKey') as any;
  const visitorId = c.req.param('id');

  if (!apiKey?.public_key || !String(apiKey.public_key).startsWith('pk_live_wayl')) {
    return c.json({ error: 'Restricted to Wayl operator keys.' }, 403);
  }

  try {
    const [profile, links] = await Promise.all([
      db.query(
        `SELECT f.*, k.name AS merchant_name
         FROM fingerprints f
         JOIN api_keys k ON k.id = f.api_key_id
         WHERE f.visitor_id = $1
         ORDER BY f.last_seen DESC
         LIMIT 1`,
        [visitorId]
      ),
      db.query(
        `SELECT visitor_id_a, visitor_id_b, link_type, confidence, created_at
         FROM device_links
         WHERE visitor_id_a = $1 OR visitor_id_b = $1
         ORDER BY confidence DESC
         LIMIT 20`,
        [visitorId]
      ),
    ]);

    if (profile.rows.length === 0) return c.json({ error: 'Visitor not found' }, 404);

    const p = profile.rows[0];
    return c.json({
      visitorId,
      merchantName: p.merchant_name,
      firstSeen: p.first_seen,
      lastSeen: p.last_seen,
      visitCount: p.visit_count,
      ipAddress: p.ip_address,
      isVpn: p.is_vpn,
      isIncognito: p.is_incognito,
      headlessScore: p.headless_score,
      botScore: p.bot_score,
      signalGroups: [
        { name: 'Canvas',   hash: p.canvas_hash,   signals: ['Canvas rendering'],                   icon: 'render' },
        { name: 'WebGL',    hash: p.webgl_hash,    signals: ['WebGL params', 'Pixel render hash'],  icon: 'gpu' },
        { name: 'Audio',    hash: p.audio_hash,    signals: ['Audio pipeline'],                     icon: 'audio' },
        { name: 'Screen',   hash: p.screen_hash,   signals: ['Screen info', 'ClientRects/DOMRect'], icon: 'display' },
        { name: 'Fonts',    hash: p.font_hash,     signals: ['System fonts', 'Arabic fonts', 'Emoji render'], icon: 'type' },
        { name: 'Browser',  hash: p.browser_hash,  signals: ['Intl API probe', 'CSS.supports()', 'Media codecs', 'SpeechSynthesis voices'], icon: 'browser' },
        { name: 'Hardware', hash: p.hardware_hash, signals: ['Hardware specs', 'MathML render', 'Browser basics'], icon: 'cpu' },
      ].filter(g => g.hash),
      linkedDevices: links.rows.map((l: any) => ({
        linkedId: l.visitor_id_a === visitorId ? l.visitor_id_b : l.visitor_id_a,
        linkType: l.link_type,
        confidence: l.confidence,
        linkedAt: l.created_at,
      })),
    });
  } catch (err: any) {
    return c.json({ error: 'Visitor query failed', details: err.message }, 500);
  }
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// FINGERPRINT ENDPOINT — v3 with weighted matching
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

    const legacyHashes = {
      composite: h(stableCore),
      canvas:    h(signals.canvas),
      webgl:     h(signals.webgl),
      audio:     h(signals.audio),
      screen:    h(signals.screen),
      fonts:     h(signals.fonts),
      browser:   h(signals.browser),
      hardware:  h(signals.hardware),
    };

    // v3 optimized grouped hashes — volatile signals (storageQuota, permissions, timezone)
    // excluded from matching hashes to prevent unnecessary mismatches.
    // Each group pairs signals with similar stability and entropy.
    const hashes = {
      composite: legacyHashes.composite,
      canvas: h(signals.canvas),                                                    // rendering fingerprint
      webgl: h({ webgl: signals.webgl, webglRender: signals.webglRender }),          // GPU identity (pixel-level)
      audio: h(signals.audio),                                                       // audio pipeline
      screen: h({ screen: signals.screen, clientRects: signals.clientRects }),        // display geometry
      fonts: h({                                                                     // glyph environment
        fonts: signals.fonts, arabicFonts: signals.arabicFonts, emoji: signals.emoji,
      }),
      browser: h({                                                                   // deep platform probe (HIGH ENTROPY)
        intlProbe: signals.intlProbe, cssSupports: signals.cssSupports,
        codecs: signals.codecs, voices: signals.voices,
      }),
      hardware: h({                                                                  // basic platform identity
        hardware: signals.hardware, mathml: signals.mathml, browser: signals.browser,
      }),
    };

    // Individual signal hashes for all 22 signals — returned in API response for transparency
    const signalNames = [
      'canvas', 'webgl', 'webglRender', 'audio', 'screen', 'clientRects',
      'fonts', 'arabicFonts', 'emoji', 'voices', 'codecs', 'cssSupports',
      'permissions', 'storageQuota', 'mathml', 'intlProbe', 'hardware',
      'browser', 'timezone',
    ];
    const signalHashes: Record<string, string> = {};
    let signalsCollected = 0;
    for (const name of signalNames) {
      const val = signals[name];
      if (val !== null && val !== undefined) {
        signalHashes[name] = h(val);
        signalsCollected++;
      }
    }

    // headlessScore is a 0-1 float; cast to 0-100 integer for the INTEGER DB column
    const headlessScoreInt = Math.round((evasion?.headlessScore || 0) * 100);
    const botCount = Object.values(evasion?.bot || {}).filter(Boolean).length;
    const normalizedClientIp = normalizeIp(clientIp);

    const isIPv4 = (ip: string) => /^(\d{1,3}\.){3}\d{1,3}$/.test(ip);
    const isIPv6 = (ip: string) => ip.includes(':');

    const webrtcIps: string[] = Array.isArray(evasion?.webrtcIPs)
      ? evasion.webrtcIPs.map((ip: string) => normalizeIp(ip)).filter(Boolean)
      : [];
    const publicWebrtcIps = webrtcIps.filter((ip) => !isPrivateIp(ip));

    // ─── VPN DETECTION (multi-signal) ───
    const cfData = (c.req.raw as any).cf || {};
    const ipTimezone: string = (cfData.timezone || '');
    const browserTimezone: string = (signals.timezone?.tz || '');
    const browserOffset: number = typeof signals.timezone?.offset === 'number' ? signals.timezone.offset : NaN;

    // Compute UTC offset (in minutes, east-positive) from an IANA timezone name.
    // Workers have full V8 Intl support.
    const getIanaOffset = (iana: string): number | null => {
      try {
        if (!iana) return null;
        const now = new Date();
        const utcStr = now.toLocaleString('en-US', { timeZone: 'UTC' });
        const tzStr  = now.toLocaleString('en-US', { timeZone: iana });
        return (new Date(tzStr).getTime() - new Date(utcStr).getTime()) / 60000;
      } catch { return null; }
    };

    let vpnScore = 0;

    // (a) Timezone offset mismatch — strongest signal.
    //   Instead of comparing IANA names (which breaks for mobile carriers routing through
    //   nearby-country gateways, e.g. "Asia/Kuwait" vs "Asia/Baghdad" → same region, ±1h),
    //   compare the actual UTC offset. Only flag if the difference exceeds 2 hours (120 min),
    //   which catches VPNs to distant locations while ignoring regional carrier routing.
    const ipOffsetMin = getIanaOffset(ipTimezone);   // +180 for UTC+3 (Baghdad)
    // Browser's getTimezoneOffset() returns UTC−local, so negate to get east-positive:
    const browserOffsetMin = !isNaN(browserOffset) ? -browserOffset : null;

    if (ipOffsetMin !== null && browserOffsetMin !== null) {
      const diffMinutes = Math.abs(ipOffsetMin - browserOffsetMin);
      if (diffMinutes > 120) {
        vpnScore += 3;   // far-away VPN (US, Asia, etc.)
      }
    }

    // (b) Known VPN / datacenter ASN keywords — catches nearby VPNs that pass timezone check
    const asOrg: string = (cfData.asOrganization || '').toLowerCase();
    const vpnAsKeywords = [
      'nordvpn', 'expressvpn', 'surfshark', 'cyberghost', 'mullvad', 'protonvpn',
      'private internet', 'purevpn', 'ipvanish', 'hotspot shield', 'windscribe',
      'torguard', 'hide.me', 'tunnelbear',
      // Common datacenter providers (IPs never used by real ISPs)
      'ovh', 'hetzner', 'digitalocean', 'digital ocean', 'vultr', 'linode',
      'choopa', 'm247', 'datacamp', 'psychz',
    ];
    if (asOrg && vpnAsKeywords.some((kw) => asOrg.includes(kw))) {
      vpnScore += 3;
    }

    // (c) Classic WebRTC leak — same-protocol IP mismatch
    if (normalizedClientIp && normalizedClientIp !== '0.0.0.0' && !isPrivateIp(normalizedClientIp)) {
      const clientIsIPv4 = isIPv4(normalizedClientIp);
      const sameProtoWebrtcIps = publicWebrtcIps.filter((ip) =>
        clientIsIPv4 ? isIPv4(ip) : isIPv6(ip)
      );
      if (sameProtoWebrtcIps.length > 0 && sameProtoWebrtcIps.every((ip) => ip !== normalizedClientIp)) {
        vpnScore += 2;
      }
    }

    // Threshold: score ≥ 2 = VPN.
    let isVpn = vpnScore >= 2;

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // IDENTITY RESOLUTION — 5-tier matching pipeline
    // The goal: know it's the same PERSON even across
    // different browsers, devices, VPNs, IP changes.
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    let visitorId: string;
    let isNew = true;
    let matchConfidence = 1.0;
    let matchTier = 'new';
    let matchedSignals: string[] = [];
    let ipChanged = false;           // did the IP change from last visit?
    let previousIp: string | null = null;

    // Helper: insert a new fingerprint row for a known visitor (alias/new device print)
    const insertAlias = async (vid: string) => {
      await db.query(
        `INSERT INTO fingerprints
          (visitor_id, raw_hash, canvas_hash, webgl_hash, audio_hash,
           screen_hash, font_hash, browser_hash, hardware_hash,
           ip_address, is_vpn, is_incognito, headless_score, bot_score, api_key_id)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
        [vid, hashes.composite, hashes.canvas, hashes.webgl, hashes.audio,
         hashes.screen, hashes.fonts, hashes.browser, hashes.hardware,
         clientIp, isVpn, evasion?.isPrivate || false, headlessScoreInt, botCount,
         apiKeyId]
      );
    };

    // Helper: create a device_link between two visitors (idempotent)
    const linkDevices = async (vidA: string, vidB: string, linkType: string, conf: number) => {
      if (vidA === vidB) return;
      const [a, b] = [vidA, vidB].sort(); // canonical order
      await db.query(
        `INSERT INTO device_links (visitor_id_a, visitor_id_b, link_type, confidence, api_key_id)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT DO NOTHING`,
        [a, b, linkType, conf, apiKeyId]
      );
    };

    // ─── Tier 0: StoredId recovery ───────────────────
    // The SDK persists visitor_id in localStorage, sessionStorage, cookies, and IndexedDB.
    // If a stored ID references a known visitor, that's the STRONGEST proof of identity —
    // it means the same browser sent us the ID we assigned previously.
    // This catches: VPN on/off, browser updates, cleared canvas data, etc.
    const clientStoredIds = storedIds || {};
    const knownVids = [clientStoredIds.ls, clientStoredIds.ss, clientStoredIds.ck, clientStoredIds.legacy]
      .filter((id: any): id is string => typeof id === 'string' && id.startsWith('dvc_'));

    let storedIdMatch: string | null = null;
    if (knownVids.length > 0) {
      const storedResult = await db.query(
        `SELECT visitor_id, ip_address FROM fingerprints
         WHERE visitor_id = ANY($1::text[]) AND api_key_id = $2
         ORDER BY last_seen DESC LIMIT 1`,
        [knownVids, apiKeyId]
      );
      if (storedResult.rows.length > 0) {
        storedIdMatch = storedResult.rows[0].visitor_id;
        previousIp = normalizeIp(storedResult.rows[0].ip_address);
      }
    }

    if (storedIdMatch) {
      // Same person — possibly different fingerprint (VPN, browser update, etc.)
      visitorId = storedIdMatch;
      isNew = false;
      matchConfidence = 0.99;
      matchTier = 'stored_id';

      // Check if IP changed — strong indicator of VPN/proxy/network switch
      if (previousIp && previousIp !== normalizedClientIp) {
        ipChanged = true;
      }

      // Check if this exact composite hash already exists
      const aliasExists = await db.query(
        'SELECT 1 FROM fingerprints WHERE raw_hash = $1 AND visitor_id = $2 AND api_key_id = $3 LIMIT 1',
        [hashes.composite, visitorId, apiKeyId]
      );
      if (aliasExists.rows.length > 0) {
        // Same fingerprint — just update
        await db.query(
          `UPDATE fingerprints SET last_seen = NOW(), visit_count = visit_count + 1, ip_address = $1
           WHERE visitor_id = $2 AND api_key_id = $3 AND raw_hash = $4`,
          [clientIp, visitorId, apiKeyId, hashes.composite]
        );
      } else {
        // New fingerprint for known person — store alias
        await insertAlias(visitorId);
      }

    // ─── Tier 1: Exact composite hash match ─────────
    } else {
      const exactMatch = await db.query(
        'SELECT visitor_id, ip_address FROM fingerprints WHERE raw_hash = $1 AND api_key_id = $2 LIMIT 1',
        [hashes.composite, apiKeyId]
      );

      if (exactMatch.rows.length > 0) {
        visitorId = exactMatch.rows[0].visitor_id;
        isNew = false;
        matchConfidence = 1.0;
        matchTier = 'exact';
        previousIp = normalizeIp(exactMatch.rows[0].ip_address);
        if (previousIp && previousIp !== normalizedClientIp) ipChanged = true;

        await db.query(
          `UPDATE fingerprints SET last_seen = NOW(), visit_count = visit_count + 1, ip_address = $1
           WHERE visitor_id = $2 AND api_key_id = $3`,
          [clientIp, visitorId, apiKeyId]
        );

      } else {
        // ─── Tier 2: Weighted fuzzy match ─────────────
        const candidates = await db.query(
          `SELECT visitor_id, ip_address, canvas_hash, webgl_hash, audio_hash,
                  screen_hash, font_hash, browser_hash, hardware_hash
           FROM fingerprints
           WHERE api_key_id = $1
           ORDER BY last_seen DESC
           LIMIT 250`,
          [apiKeyId]
        );

        const weights: Record<string, number> = {
          browser:  0.20,
          webgl:    0.16,
          fonts:    0.16,
          canvas:   0.14,
          screen:   0.12,
          hardware: 0.12,
          audio:    0.10,
        };

        let bestScore = 0;
        let bestCandidate: any = null;
        let bestMatched: string[] = [];

        for (const cand of candidates.rows) {
          let score = 0;
          let total = 0;
          const matched: string[] = [];

          const pairs = [
            { key: 'canvas',   values: [hashes.canvas, legacyHashes.canvas],   stored: cand.canvas_hash },
            { key: 'webgl',    values: [hashes.webgl, legacyHashes.webgl],     stored: cand.webgl_hash },
            { key: 'audio',    values: [hashes.audio, legacyHashes.audio],     stored: cand.audio_hash },
            { key: 'screen',   values: [hashes.screen, legacyHashes.screen],   stored: cand.screen_hash },
            { key: 'hardware', values: [hashes.hardware, legacyHashes.hardware],stored: cand.hardware_hash },
            { key: 'fonts',    values: [hashes.fonts, legacyHashes.fonts],     stored: cand.font_hash },
            { key: 'browser',  values: [hashes.browser, legacyHashes.browser], stored: cand.browser_hash },
          ];

          for (const { key, values, stored } of pairs) {
            if (!stored) continue;
            const incoming = values.filter(Boolean);
            if (incoming.length === 0) continue;
            total += weights[key];
            if (incoming.includes(stored)) {
              score += weights[key];
              matched.push(key);
            }
          }

          const highEntropyMatches = ['canvas', 'webgl', 'fonts', 'browser'].filter((k) => matched.includes(k)).length;
          if (highEntropyMatches >= 3) score += 0.08;
          if (highEntropyMatches >= 2 && normalizeIp(cand.ip_address) === normalizedClientIp) score += 0.04;

          const normalized = total > 0 ? score / total : 0;
          if (normalized > bestScore) {
            bestScore = normalized;
            bestCandidate = cand;
            bestMatched = matched;
          }
        }

        const MATCH_THRESHOLD = 0.58;

        if (bestCandidate && bestScore >= MATCH_THRESHOLD) {
          visitorId = bestCandidate.visitor_id;
          isNew = false;
          matchConfidence = Math.round(bestScore * 100) / 100;
          matchTier = 'fuzzy';
          matchedSignals = bestMatched;
          previousIp = normalizeIp(bestCandidate.ip_address);
          if (previousIp && previousIp !== normalizedClientIp) ipChanged = true;
          await insertAlias(visitorId);

        // ─── Tier 3: Cross-device network linking ─────
        // Same IP + at least 2 matching signal groups = likely same household/person.
        // Creates a NEW visitor_id but LINKS it to the existing one.
        // This catches: dad's phone, son's phone, same WiFi.
        } else {
          // Also check partial fuzzy matches (below threshold) for cross-device links
          const LINK_THRESHOLD = 0.30;
          let linkCandidate: any = null;
          let linkScore = 0;
          let linkMatched: string[] = [];

          // Re-evaluate best candidate at lower threshold, prioritizing same-IP peers
          for (const cand of candidates.rows) {
            const sameIp = normalizeIp(cand.ip_address) === normalizedClientIp;
            let score = 0;
            let total = 0;
            const matched: string[] = [];

            const pairs = [
              { key: 'canvas',   values: [hashes.canvas, legacyHashes.canvas],   stored: cand.canvas_hash },
              { key: 'webgl',    values: [hashes.webgl, legacyHashes.webgl],     stored: cand.webgl_hash },
              { key: 'audio',    values: [hashes.audio, legacyHashes.audio],     stored: cand.audio_hash },
              { key: 'screen',   values: [hashes.screen, legacyHashes.screen],   stored: cand.screen_hash },
              { key: 'hardware', values: [hashes.hardware, legacyHashes.hardware],stored: cand.hardware_hash },
              { key: 'fonts',    values: [hashes.fonts, legacyHashes.fonts],     stored: cand.font_hash },
              { key: 'browser',  values: [hashes.browser, legacyHashes.browser], stored: cand.browser_hash },
            ];

            for (const { key, values, stored } of pairs) {
              if (!stored) continue;
              const incoming = values.filter(Boolean);
              if (incoming.length === 0) continue;
              total += weights[key];
              if (incoming.includes(stored)) {
                score += weights[key];
                matched.push(key);
              }
            }

            const normalized = total > 0 ? score / total : 0;

            // Cross-device link requires: (same IP + ≥1 signal match) OR (≥2 signal matches on any IP)
            const qualifies = (sameIp && matched.length >= 1) || matched.length >= 2;

            if (qualifies && normalized > linkScore && normalized >= LINK_THRESHOLD) {
              linkScore = normalized;
              linkCandidate = cand;
              linkMatched = matched;
            }
          }

          // Create new visitor but LINK to the candidate
          visitorId = `dvc_${nanoid(16)}`;
          matchConfidence = 1.0;

          if (linkCandidate) {
            matchTier = 'cross_device';
            matchedSignals = linkMatched;
            await insertAlias(visitorId);
            // Create device link
            const linkConf = Math.round(linkScore * 100) / 100;
            const sameIp = normalizeIp(linkCandidate.ip_address) === normalizedClientIp;
            const linkType = sameIp ? 'same_network' : 'signal_overlap';
            await linkDevices(visitorId, linkCandidate.visitor_id, linkType, linkConf);
          } else {
            matchTier = 'new';
            await insertAlias(visitorId);
          }
        }
      }
    }

    // ─── Linked devices (fetch all links for this visitor + transitive) ───
    const linkedResult = await db.query(
      `SELECT visitor_id_a, visitor_id_b, link_type, confidence, created_at
       FROM device_links
       WHERE (visitor_id_a = $1 OR visitor_id_b = $1) AND api_key_id = $2
       ORDER BY confidence DESC`,
      [visitorId, apiKeyId]
    );

    // Collect all linked visitor IDs
    const linkedVids = linkedResult.rows.map((l: any) =>
      l.visitor_id_a === visitorId ? l.visitor_id_b : l.visitor_id_a
    );

    // ─── Cumulative risk: inherit risk flags from linked devices ───
    // If ANY linked visitor was flagged for VPN/incognito/bot/headless,
    // this visitor inherits elevated risk — you can't escape by switching devices.
    let linkedRiskFlags = { vpn: false, incognito: false, headless: false, bot: false };
    if (linkedVids.length > 0) {
      const linkedRiskResult = await db.query(
        `SELECT is_vpn, is_incognito, headless_score, bot_score
         FROM fingerprints
         WHERE visitor_id = ANY($1::text[]) AND api_key_id = $2
         ORDER BY last_seen DESC
         LIMIT 50`,
        [linkedVids, apiKeyId]
      );
      for (const row of linkedRiskResult.rows) {
        if (row.is_vpn) linkedRiskFlags.vpn = true;
        if (row.is_incognito) linkedRiskFlags.incognito = true;
        if ((row.headless_score || 0) >= 40) linkedRiskFlags.headless = true;
        if ((row.bot_score || 0) >= 2) linkedRiskFlags.bot = true;
      }
    }

    // Secondary VPN heuristic: IP rotation (4+ distinct IPs in 1 hour)
    const recentIpsResult = await db.query(
      `SELECT DISTINCT ip_address
       FROM fingerprints
       WHERE visitor_id = $1 AND api_key_id = $2
         AND ip_address IS NOT NULL
         AND last_seen >= NOW() - INTERVAL '1 hour'
       LIMIT 10`,
      [visitorId, apiKeyId]
    );
    const distinctRecentPublicIps = recentIpsResult.rows
      .map((row: any) => normalizeIp(row.ip_address))
      .filter((ip: string) => !!ip && !isPrivateIp(ip));
    const vpnByIpRotation = new Set(distinctRecentPublicIps).size >= 4;

    // IP change detection: if stored_id or exact match found the same person
    // but the IP is different, that's a network switch (VPN, mobile data, etc.)
    const vpnByIpSwitch = ipChanged && !isNew;

    const finalIsVpn = isVpn || vpnByIpRotation || vpnByIpSwitch;

    // ─── Risk scoring (cumulative — inherits from linked devices) ───
    let riskScore = 0;
    if (isNew && linkedVids.length === 0) riskScore += 15;   // truly new, no links
    if (finalIsVpn)                        riskScore += 25;
    if (evasion?.isPrivate)                riskScore += 20;
    if ((evasion?.headlessScore || 0) > 0.4) riskScore += 30;
    if (botCount > 0)                      riskScore += 35;
    if (linkedResult.rows.length > 3)      riskScore += 15;   // multi-device cluster
    const tampering = evasion?.tampering || {};
    if (tampering.canvasOverride)    riskScore += 20;
    if (tampering.uaOverride)        riskScore += 15;
    if (tampering.navigatorProxy)    riskScore += 20;
    if (tampering.genericRenderer)   riskScore += 10;
    if (tampering.screenMismatch)    riskScore += 15;
    // Inherited risk from linked devices
    if (linkedRiskFlags.vpn)         riskScore += 15;
    if (linkedRiskFlags.bot)         riskScore += 20;
    if (linkedRiskFlags.headless)    riskScore += 15;
    if (linkedRiskFlags.incognito)   riskScore += 10;
    // IP change without VPN detection = suspicious
    if (ipChanged && !finalIsVpn)    riskScore += 10;
    riskScore = Math.min(100, Math.max(0, riskScore));

    return c.json({
      visitorId,
      isNew,
      confidence: isNew ? 1.0 : matchConfidence,
      matchTier,
      matchedSignals: matchedSignals.length > 0 ? matchedSignals : undefined,
      riskScore,
      riskSignals: {
        vpn: finalIsVpn,
        incognito: evasion?.isPrivate || false,
        headless: (evasion?.headlessScore || 0) > 0.4,
        bot: botCount >= 2,
        tampered: !!(tampering.canvasOverride || tampering.uaOverride || tampering.navigatorProxy),
        multiAccount: linkedResult.rows.length > 1,
        ipChanged,
        linkedRisk: linkedRiskFlags,
      },
      identity: {
        linkedDeviceCount: linkedResult.rows.length,
        linkedVisitorIds: linkedVids,
        links: linkedResult.rows.map((l: any) => ({
          visitorId: l.visitor_id_a === visitorId ? l.visitor_id_b : l.visitor_id_a,
          linkType: l.link_type,
          confidence: l.confidence,
          linkedAt: l.created_at,
        })),
        previousIp: ipChanged ? previousIp : undefined,
        currentIp: clientIp,
      },
      signals: {
        collected: signalsCollected,
        total: signalNames.length,
        hashes: signalHashes,
        groups: {
          canvas:   { hash: hashes.canvas,   signals: ['canvas'] },
          webgl:    { hash: hashes.webgl,    signals: ['webgl', 'webglRender'] },
          audio:    { hash: hashes.audio,    signals: ['audio'] },
          screen:   { hash: hashes.screen,   signals: ['screen', 'clientRects'] },
          fonts:    { hash: hashes.fonts,    signals: ['fonts', 'arabicFonts', 'emoji'] },
          browser:  { hash: hashes.browser,  signals: ['intlProbe', 'cssSupports', 'codecs', 'voices'] },
          hardware: { hash: hashes.hardware, signals: ['hardware', 'mathml', 'browser'] },
        },
      },
      ip: clientIp,
      geo: {
        country: cfData.country || null,
        region: cfData.region || null,
        city: cfData.city || null,
        timezone: cfData.timezone || null,
        asn: cfData.asn || null,
        asOrganization: cfData.asOrganization || null,
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
