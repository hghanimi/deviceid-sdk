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
    const [overview, merchants, riskyEvents, hourly, allEventsQ, linkedCountQ, eventLogQ] = await Promise.all([
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
      // Per-visit event log from the events table
      db.query(
        `SELECT e.visitor_id, e.event_type, e.event_data, e.ip_address, e.created_at,
                k.name AS merchant_name
         FROM events e
         JOIN api_keys k ON k.id = e.api_key_id
         WHERE e.created_at >= NOW() - INTERVAL '24 hours'
         ORDER BY e.created_at DESC
         LIMIT 200`
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
      eventLog: eventLogQ.rows.map((row: any) => ({
        visitorId: row.visitor_id,
        eventType: row.event_type,
        eventData: row.event_data,
        ipAddress: row.ip_address,
        merchantName: row.merchant_name,
        createdAt: row.created_at,
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

    // ─── PROXY TYPE CLASSIFICATION ───
    // Differentiate: VPN / datacenter / residential proxy / relay / none
    const datacenterKeywords = [
      'ovh', 'hetzner', 'digitalocean', 'digital ocean', 'vultr', 'linode',
      'choopa', 'm247', 'datacamp', 'psychz', 'amazon', 'google cloud',
      'microsoft azure', 'cloudflare', 'oracle', 'scaleway', 'contabo',
      'leaseweb', 'equinix', 'rackspace', 'kamatera',
    ];
    const vpnKeywords = [
      'nordvpn', 'expressvpn', 'surfshark', 'cyberghost', 'mullvad', 'protonvpn',
      'private internet', 'purevpn', 'ipvanish', 'hotspot shield', 'windscribe',
      'torguard', 'hide.me', 'tunnelbear',
    ];
    let proxyType = 'none';
    let proxyConfidence = 'low';
    const isDatacenter = datacenterKeywords.some((kw) => asOrg.includes(kw));
    const isVpnAsn = vpnKeywords.some((kw) => asOrg.includes(kw));
    if (isVpnAsn) { proxyType = 'vpn'; proxyConfidence = 'high'; }
    else if (isDatacenter) { proxyType = 'datacenter'; proxyConfidence = 'high'; }
    else if (isVpn && !isDatacenter) { proxyType = 'residential'; proxyConfidence = 'medium'; }

    // ─── IP BLOCKLIST CHECK ───
    // Heuristic blocklist: check if IP's ASN belongs to known bad-actor ranges
    const blocklist = {
      result: false,
      details: { emailSpam: false, attackSource: false, datacenter: isDatacenter }
    };
    // Tor exit node detection via Cloudflare header
    const isTor = (cfData.isTor === true || cfData.isTor === 'true');
    if (isTor) { blocklist.result = true; blocklist.details.attackSource = true; proxyType = 'tor'; }

    // ─── LOCATION SPOOFING (server-side cross-check) ───
    const locSpoof = evasion?.locationSpoofing || {};
    let locationSpoofResult = false;
    if (locSpoof.signals) {
      // Compare browser-reported timezone with IP timezone
      const browserTz = locSpoof.signals.timezone || browserTimezone;
      const ipOff = ipOffsetMin;
      const brOff = locSpoof.signals.offset != null ? -locSpoof.signals.offset : browserOffsetMin;
      if (ipOff != null && brOff != null && Math.abs(ipOff - brOff) > 120) {
        locationSpoofResult = true;
      }
      // Clock drift from client
      if (locSpoof.signals.clockDrift > 5000) locationSpoofResult = true;
    }

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
           ip_address, country, first_seen, last_seen, visit_count,
           is_vpn, is_incognito, headless_score, bot_score, api_key_id)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW(),NOW(),1,$12,$13,$14,$15,$16)`,
        [vid, hashes.composite, hashes.canvas, hashes.webgl, hashes.audio,
         hashes.screen, hashes.fonts, hashes.browser, hashes.hardware,
         clientIp, cfData.country || null,
         isVpn, evasion?.isPrivate || false, headlessScoreInt, botCount,
         apiKeyId]
      );
    };

    // Helper: create a device_link between two visitors (idempotent)
    const linkDevices = async (vidA: string, vidB: string, linkType: string, conf: number) => {
      if (vidA === vidB) return;
      const [a, b] = [vidA, vidB].sort(); // canonical order
      try {
        await db.query(
          `INSERT INTO device_links (visitor_id_a, visitor_id_b, link_type, confidence, api_key_id)
           VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT DO NOTHING`,
          [a, b, linkType, conf, apiKeyId]
        );
      } catch (e) {
        // Non-fatal — linking failure shouldn't break fingerprinting
        console.error('linkDevices error:', e);
      }
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
    let linkedResult = { rows: [] as any[] };
    try {
      linkedResult = await db.query(
        `SELECT visitor_id_a, visitor_id_b, link_type, confidence, created_at
         FROM device_links
         WHERE (visitor_id_a = $1 OR visitor_id_b = $1) AND api_key_id = $2
         ORDER BY confidence DESC`,
        [visitorId, apiKeyId]
      );
    } catch (e) {
      console.error('device_links query error:', e);
    }

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

    // ─── VELOCITY SIGNALS (events/IPs over time windows) ───
    let velocity = {
      distinctIp: { '5m': 0, '1h': 0, '24h': 0 },
      events: { '5m': 0, '1h': 0, '24h': 0 },
      distinctCountry: { '5m': 0, '1h': 0, '24h': 0 },
      ipEvents: { '5m': 0, '1h': 0, '24h': 0 },
    };
    try {
      const [vel5m, vel1h, vel24h, ipVel] = await Promise.all([
        db.query(
          `SELECT COUNT(*)::int AS events,
                  COUNT(DISTINCT ip_address)::int AS distinct_ip
           FROM events WHERE visitor_id = $1 AND api_key_id = $2
             AND created_at >= NOW() - INTERVAL '5 minutes'`,
          [visitorId, apiKeyId]
        ),
        db.query(
          `SELECT COUNT(*)::int AS events,
                  COUNT(DISTINCT ip_address)::int AS distinct_ip
           FROM events WHERE visitor_id = $1 AND api_key_id = $2
             AND created_at >= NOW() - INTERVAL '1 hour'`,
          [visitorId, apiKeyId]
        ),
        db.query(
          `SELECT COUNT(*)::int AS events,
                  COUNT(DISTINCT ip_address)::int AS distinct_ip
           FROM events WHERE visitor_id = $1 AND api_key_id = $2
             AND created_at >= NOW() - INTERVAL '24 hours'`,
          [visitorId, apiKeyId]
        ),
        db.query(
          `SELECT COUNT(*)::int AS ip_events
           FROM events WHERE ip_address = $1 AND api_key_id = $2
             AND created_at >= NOW() - INTERVAL '24 hours'`,
          [clientIp, apiKeyId]
        ),
      ]);
      velocity.events['5m'] = vel5m.rows[0]?.events || 0;
      velocity.events['1h'] = vel1h.rows[0]?.events || 0;
      velocity.events['24h'] = vel24h.rows[0]?.events || 0;
      velocity.distinctIp['5m'] = vel5m.rows[0]?.distinct_ip || 0;
      velocity.distinctIp['1h'] = vel1h.rows[0]?.distinct_ip || 0;
      velocity.distinctIp['24h'] = vel24h.rows[0]?.distinct_ip || 0;
      velocity.ipEvents['5m'] = Math.min(vel5m.rows[0]?.events || 0, velocity.events['5m']);
      velocity.ipEvents['1h'] = Math.min(vel1h.rows[0]?.events || 0, velocity.events['1h']);
      velocity.ipEvents['24h'] = ipVel.rows[0]?.ip_events || 0;
    } catch (e) {
      console.error('Velocity query error:', e);
    }
    const highActivity = velocity.events['1h'] > 20 || velocity.events['5m'] > 10;

    // ─── Risk scoring (contextual — VPN alone ≠ risky) ───
    // Philosophy: normal people use VPNs, incognito, new devices.
    // Risk = evasion INTENT, measured by combining multiple signals.
    let riskScore = 0;

    // Count evasion layers — risk compounds when stacked
    const evasionLayers =
      (finalIsVpn ? 1 : 0) +
      (evasion?.isPrivate ? 1 : 0) +
      (ipChanged ? 1 : 0) +
      (botCount > 0 ? 1 : 0) +
      ((evasion?.headlessScore || 0) > 0.4 ? 1 : 0);

    // ── VPN: only risky when combined with other evasion ──
    if (finalIsVpn) {
      if (evasionLayers >= 3)        riskScore += 25;  // VPN + incognito + bot/headless = serious
      else if (evasionLayers >= 2)   riskScore += 15;  // VPN + one other signal = moderate
      else                           riskScore += 5;   // VPN alone = negligible (normal user)
    }

    // ── Incognito: same logic — alone is fine ──
    if (evasion?.isPrivate) {
      if (evasionLayers >= 3)        riskScore += 20;
      else if (evasionLayers >= 2)   riskScore += 10;
      else                           riskScore += 3;   // incognito alone = negligible
    }

    // ── Hard signals — these ARE inherently suspicious ──
    if ((evasion?.headlessScore || 0) > 0.4) riskScore += 30;  // headless browser
    if (botCount > 0)                        riskScore += 35;  // bot behavior
    const tampering = evasion?.tampering || {};
    if (tampering.canvasOverride)    riskScore += 20;
    if (tampering.uaOverride)        riskScore += 15;
    if (tampering.navigatorProxy)    riskScore += 20;
    if (tampering.genericRenderer)   riskScore += 10;
    if (tampering.screenMismatch)    riskScore += 15;

    // ── Contextual signals ──
    if (linkedResult.rows.length > 3)      riskScore += 10;   // large device cluster
    if (ipChanged && !finalIsVpn)          riskScore += 10;   // IP changed without VPN = sus
    if (isNew && evasionLayers >= 2)       riskScore += 10;   // new + hiding = sus
    // New device alone = 0 risk (everyone is new once)

    // Inherited risk from linked devices (reduced weights)
    if (linkedRiskFlags.bot)         riskScore += 15;
    if (linkedRiskFlags.headless)    riskScore += 10;
    if (linkedRiskFlags.vpn && linkedRiskFlags.incognito) riskScore += 10; // linked device was hiding

    // ── New v3.1 signals ──
    const devToolsOpen = evasion?.devTools?.open || false;
    const vmResult = evasion?.virtualMachine?.result || false;
    if (vmResult)                    riskScore += 15;   // virtual machine
    if (locationSpoofResult)         riskScore += 20;   // spoofing location
    if (highActivity)                riskScore += 10;   // velocity anomaly
    if (isTor)                       riskScore += 25;   // Tor exit node
    riskScore = Math.min(100, Math.max(0, riskScore));

    // ─── Log every visit to the events table (audit trail) ───
    try {
      await db.query(
        `INSERT INTO events (visitor_id, event_type, event_data, ip_address, api_key_id)
         VALUES ($1, $2, $3::jsonb, $4, $5)`,
        [visitorId, 'identify', JSON.stringify({
          matchTier,
          confidence: isNew ? 1.0 : matchConfidence,
          riskScore,
          isVpn: finalIsVpn,
          ipChanged,
          isNew,
          signalsCollected,
          proxyType,
          highActivity,
          userAgent: c.req.header('User-Agent') || null,
        }), clientIp, apiKeyId]
      );
    } catch (e) {
      console.error('Event log error:', e);
    }

    // ─── Build Fingerprint Pro-style products response ───
    const browserUA = c.req.header('User-Agent') || '';
    const uaMatch = browserUA.match(/(Chrome|Firefox|Safari|Edge|Opera)\/(\d+)/);
    const browserName = uaMatch ? uaMatch[1] : 'Other';
    const browserMajorVersion = uaMatch ? uaMatch[2] : '0';
    const osMatch = browserUA.match(/(Windows NT [\d.]+|Mac OS X [\d_]+|Linux|Android [\d.]+|iPhone OS [\d_]+)/);
    const osInfo = osMatch ? osMatch[1] : 'Other';

    return c.json({
      // ── Core identification (matches FP Pro) ──
      visitorId,
      requestId: `${Date.now()}.${visitorId.substring(4, 10)}`,
      isNew,
      confidence: { score: isNew ? 1.0 : matchConfidence, revision: 'v1.0' },
      matchTier,
      matchedSignals: matchedSignals.length > 0 ? matchedSignals : undefined,
      visitorFound: !isNew,
      firstSeenAt: null, // populated from DB on return visits
      lastSeenAt: null,
      browserDetails: {
        browserName,
        browserMajorVersion,
        os: osInfo,
        userAgent: browserUA,
        device: /Mobile|Android|iPhone/.test(browserUA) ? 'Mobile' : 'Other',
      },

      // ── Products (matching FP Pro structure) ──
      products: {
        identification: {
          data: { visitorId, confidence: { score: isNew ? 1.0 : matchConfidence }, isNew, matchTier }
        },
        botd: {
          data: {
            bot: { result: botCount >= 2 ? 'detected' : 'notDetected', score: botCount },
            meta: { ip: clientIp }
          }
        },
        vpn: {
          data: {
            result: finalIsVpn,
            confidence: proxyConfidence,
            originTimezone: browserTimezone || null,
            originCountry: cfData.country || 'unknown',
            methods: {
              timezoneMismatch: vpnScore >= 3 && ipOffsetMin !== null,
              publicVPN: isVpnAsn,
              osMismatch: false,
              relay: false,
              webrtcLeak: publicWebrtcIps.length > 0 && publicWebrtcIps.every((ip: string) => ip !== normalizedClientIp),
            },
          }
        },
        proxy: {
          data: {
            result: proxyType !== 'none',
            confidence: proxyConfidence,
            details: { proxyType },
          }
        },
        tor: { data: { result: isTor } },
        ipBlocklist: { data: blocklist },
        incognito: { data: { result: evasion?.isPrivate || false } },
        tampering: {
          data: {
            result: !!(tampering.canvasOverride || tampering.uaOverride || tampering.navigatorProxy),
            anomalyScore: Object.values(tampering).filter(Boolean).length,
            antiDetectBrowser: !!(tampering.canvasOverride && tampering.uaOverride && tampering.navigatorProxy),
          }
        },
        virtualMachine: { data: { result: vmResult, details: evasion?.virtualMachine || {} } },
        developerTools: { data: { result: devToolsOpen } },
        locationSpoofing: { data: { result: locationSpoofResult, details: locSpoof.signals || {} } },
        highActivity: { data: { result: highActivity } },
        emulator: { data: { result: vmResult && /Android|Mobile/.test(browserUA) } },
        rootApps: { data: { result: false } },
        frida: { data: { result: false } },
        jailbroken: { data: { result: false } },
        clonedApp: { data: { result: false } },
        privacySettings: { data: { result: evasion?.isPrivate || false } },
        factoryReset: { data: { time: null, timestamp: 0 } },
        velocity: { data: velocity },
        suspectScore: { data: { result: riskScore } },
        ipInfo: {
          data: {
            v4: {
              address: clientIp,
              geolocation: {
                timezone: cfData.timezone || null,
                city: cfData.city ? { name: cfData.city } : null,
                country: cfData.country ? { code: cfData.country, name: cfData.country } : null,
                continent: cfData.continent ? { code: cfData.continent } : null,
                subdivisions: cfData.region ? [{ isoCode: cfData.region, name: cfData.region }] : [],
              },
              asn: {
                asn: String(cfData.asn || ''),
                name: cfData.asOrganization || '',
                type: isDatacenter ? 'hosting' : 'isp',
              },
              datacenter: { result: isDatacenter, name: isDatacenter ? cfData.asOrganization : '' },
            },
          }
        },
        rawDeviceAttributes: { data: signals.rawAttributes || {} },
      },

      // ── Legacy fields (backward compatible) ──
      riskScore,
      riskSignals: {
        vpn: finalIsVpn,
        incognito: evasion?.isPrivate || false,
        headless: (evasion?.headlessScore || 0) > 0.4,
        bot: botCount >= 2,
        tampered: !!(tampering.canvasOverride || tampering.uaOverride || tampering.navigatorProxy),
        multiAccount: linkedResult.rows.length > 1,
        ipChanged,
        tor: isTor,
        vm: vmResult,
        devTools: devToolsOpen,
        locationSpoofing: locationSpoofResult,
        highActivity,
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
        continent: cfData.continent || null,
        latitude: cfData.latitude || null,
        longitude: cfData.longitude || null,
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
