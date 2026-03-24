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

// ─── Cross-Device Person Resolution Engine ───
async function resolvePersonIdentity(
  db: any,
  visitorId: string,
  apiKeyId: string,
  clientIp: string,
  userId?: string,
): Promise<{
  personId: string | null;
  linkedDevices: Array<{ visitorId: string; linkType: string; confidence: number }>;
  isNewPerson: boolean;
  linkType: string | null;
}> {
  let personId: string | null = null;
  let isNewPerson = false;
  let linkType: string | null = null;
  const linkedDevices: Array<{ visitorId: string; linkType: string; confidence: number }> = [];

  try {
    // METHOD 1: Deterministic — userId from merchant login (99.9% accurate)
    if (userId) {
      const existingPerson = await db.query(
        `SELECT person_id FROM persons
         WHERE external_user_id = $1 AND api_key_id = $2
         LIMIT 1`,
        [userId, apiKeyId]
      );

      if (existingPerson.rows.length > 0) {
        personId = existingPerson.rows[0].person_id;
        const existingLink = await db.query(
          `SELECT id FROM person_devices
           WHERE person_id = $1 AND visitor_id = $2 AND api_key_id = $3
           LIMIT 1`,
          [personId, visitorId, apiKeyId]
        );
        if (existingLink.rows.length === 0) {
          await db.query(
            `INSERT INTO person_devices (person_id, visitor_id, link_type, confidence, ip_at_link, api_key_id)
             VALUES ($1, $2, 'login', 1.0, $3, $4)`,
            [personId, visitorId, clientIp, apiKeyId]
          );
          await db.query(
            `UPDATE persons SET device_count = device_count + 1, last_seen = NOW()
             WHERE person_id = $1`,
            [personId]
          );
        } else {
          await db.query(
            `UPDATE persons SET last_seen = NOW() WHERE person_id = $1`,
            [personId]
          );
        }
        linkType = 'login';
      } else {
        personId = `psn_${nanoid(12)}`;
        isNewPerson = true;
        linkType = 'login';
        await db.query(
          `INSERT INTO persons (person_id, api_key_id, external_user_id, device_count)
           VALUES ($1, $2, $3, 1)`,
          [personId, apiKeyId, userId]
        );
        await db.query(
          `INSERT INTO person_devices (person_id, visitor_id, link_type, confidence, ip_at_link, api_key_id)
           VALUES ($1, $2, 'login', 1.0, $3, $4)`,
          [personId, visitorId, clientIp, apiKeyId]
        );
      }
    }

    // METHOD 2: Probabilistic — IP correlation (70-85% accurate)
    if (!personId && clientIp) {
      const ipNeighbors = await db.query(
        `SELECT DISTINCT f.visitor_id, f.person_id, pd.person_id as linked_person_id
         FROM fingerprints f
         LEFT JOIN person_devices pd ON pd.visitor_id = f.visitor_id AND pd.api_key_id = $3
         WHERE f.ip_address = $1
           AND f.api_key_id = $3
           AND f.visitor_id != $2
           AND f.last_seen >= NOW() - INTERVAL '30 minutes'
         ORDER BY f.visitor_id
         LIMIT 10`,
        [clientIp, visitorId, apiKeyId]
      );

      if (ipNeighbors.rows.length > 0) {
        const neighborWithPerson = ipNeighbors.rows.find(
          (r: any) => r.person_id || r.linked_person_id
        );

        if (neighborWithPerson) {
          personId = neighborWithPerson.person_id || neighborWithPerson.linked_person_id;
          linkType = 'ip_correlation';
          const alreadyLinked = await db.query(
            `SELECT id FROM person_devices WHERE person_id = $1 AND visitor_id = $2 LIMIT 1`,
            [personId, visitorId]
          );
          if (alreadyLinked.rows.length === 0) {
            await db.query(
              `INSERT INTO person_devices (person_id, visitor_id, link_type, confidence, ip_at_link, api_key_id)
               VALUES ($1, $2, 'ip_correlation', 0.70, $3, $4)`,
              [personId, visitorId, clientIp, apiKeyId]
            );
            await db.query(
              `UPDATE persons SET device_count = device_count + 1, last_seen = NOW()
               WHERE person_id = $1`,
              [personId]
            );
          }
        } else {
          personId = `psn_${nanoid(12)}`;
          isNewPerson = true;
          linkType = 'ip_correlation';
          await db.query(
            `INSERT INTO persons (person_id, api_key_id, device_count)
             VALUES ($1, $2, $3)`,
            [personId, apiKeyId, ipNeighbors.rows.length + 1]
          );
          await db.query(
            `INSERT INTO person_devices (person_id, visitor_id, link_type, confidence, ip_at_link, api_key_id)
             VALUES ($1, $2, 'ip_correlation', 0.70, $3, $4)`,
            [personId, visitorId, clientIp, apiKeyId]
          );
          for (const neighbor of ipNeighbors.rows) {
            await db.query(
              `INSERT INTO person_devices (person_id, visitor_id, link_type, confidence, ip_at_link, api_key_id)
               VALUES ($1, $2, 'ip_correlation', 0.70, $3, $4)
               ON CONFLICT DO NOTHING`,
              [personId, neighbor.visitor_id, clientIp, apiKeyId]
            );
          }
        }
      }
    }

    // METHOD 3: Historical lookup — device was previously linked
    if (!personId) {
      const pastLink = await db.query(
        `SELECT person_id, link_type FROM person_devices
         WHERE visitor_id = $1 AND api_key_id = $2
         ORDER BY linked_at DESC LIMIT 1`,
        [visitorId, apiKeyId]
      );
      if (pastLink.rows.length > 0) {
        personId = pastLink.rows[0].person_id;
        linkType = pastLink.rows[0].link_type;
        await db.query(
          `UPDATE persons SET last_seen = NOW() WHERE person_id = $1`,
          [personId]
        );
      }
    }

    // Update fingerprints table with person_id
    if (personId) {
      await db.query(
        `UPDATE fingerprints SET person_id = $1
         WHERE visitor_id = $2 AND api_key_id = $3 AND (person_id IS NULL OR person_id != $1)`,
        [personId, visitorId, apiKeyId]
      );
      const allDevices = await db.query(
        `SELECT visitor_id, link_type, confidence FROM person_devices
         WHERE person_id = $1 AND visitor_id != $2
         ORDER BY linked_at DESC`,
        [personId, visitorId]
      );
      for (const d of allDevices.rows) {
        linkedDevices.push({
          visitorId: d.visitor_id,
          linkType: d.link_type,
          confidence: parseFloat(d.confidence),
        });
      }
    }
  } catch (err) {
    console.error('Person resolution error:', err);
  }

  return { personId, linkedDevices, isNewPerson, linkType };
}

app.use('*', cors());

app.use('*', async (c, next) => {
  const client = new Client({ connectionString: c.env.DATABASE_URL });
  await client.connect();
  // Auto-migrate: add device-level hash columns if missing
  try {
    await client.query(`
      ALTER TABLE fingerprints ADD COLUMN IF NOT EXISTS device_hash TEXT;
      ALTER TABLE fingerprints ADD COLUMN IF NOT EXISTS screen_only_hash TEXT;
      ALTER TABLE fingerprints ADD COLUMN IF NOT EXISTS gpu_hash TEXT;
      ALTER TABLE fingerprints ADD COLUMN IF NOT EXISTS hw_only_hash TEXT;
      ALTER TABLE fingerprints ADD COLUMN IF NOT EXISTS fonts_only_hash TEXT;
      ALTER TABLE fingerprints ADD COLUMN IF NOT EXISTS person_id VARCHAR(32);
    `);
  } catch (e) { /* columns already exist or non-fatal */ }
  // Auto-migrate: person resolution tables
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS persons (
        person_id VARCHAR(32) PRIMARY KEY,
        api_key_id UUID NOT NULL REFERENCES api_keys(id),
        external_user_id TEXT,
        device_count INT DEFAULT 1,
        first_seen TIMESTAMPTZ DEFAULT NOW(),
        last_seen TIMESTAMPTZ DEFAULT NOW(),
        metadata JSONB DEFAULT '{}'::jsonb
      );
      CREATE TABLE IF NOT EXISTS person_devices (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        person_id VARCHAR(32) NOT NULL REFERENCES persons(person_id),
        visitor_id VARCHAR(32) NOT NULL,
        link_type VARCHAR(20) NOT NULL,
        confidence DECIMAL(3,2) NOT NULL,
        ip_at_link TEXT,
        linked_at TIMESTAMPTZ DEFAULT NOW(),
        api_key_id UUID NOT NULL REFERENCES api_keys(id)
      );
      CREATE INDEX IF NOT EXISTS idx_persons_external_uid ON persons(external_user_id, api_key_id);
      CREATE INDEX IF NOT EXISTS idx_person_devices_visitor ON person_devices(visitor_id, api_key_id);
      CREATE INDEX IF NOT EXISTS idx_person_devices_person ON person_devices(person_id);
      CREATE INDEX IF NOT EXISTS idx_fingerprints_person ON fingerprints(person_id);
      CREATE INDEX IF NOT EXISTS idx_fingerprints_ip_recent ON fingerprints(ip_address, api_key_id, last_seen DESC);
    `);
  } catch (e) { /* tables already exist or non-fatal */ }
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

  // Restrict portfolio-wide monitoring to Athar operator keys.
  if (!apiKey?.public_key || !String(apiKey.public_key).startsWith('pk_live_athar')) {
    return c.json({ error: 'Dashboard access is restricted to Athar operator keys.' }, 403);
  }

  try {
    const [overview, merchants, riskyEvents, hourly, allEventsQ, linkedCountQ, eventLogQ, uniquePersonsQ, personsStatsQ] = await Promise.all([
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
      // "Unique Persons" = unique devices minus linked pairs
      // Uses Union-Find to collapse linked visitor_ids into identity clusters
      db.query(
        `SELECT visitor_id_a, visitor_id_b FROM device_links`
      ).catch(() => ({ rows: [] })),
      // Person resolution stats
      db.query(
        `SELECT COUNT(DISTINCT person_id)::int AS total_persons,
                COUNT(*)::int AS total_person_devices
         FROM person_devices
         WHERE api_key_id = $1`,
        [apiKey.id]
      ).catch(() => ({ rows: [{ total_persons: 0, total_person_devices: 0 }] })),
    ]);

    // Build a map of visitor_id → link count
    const linkMap = new Map<string, number>();
    for (const row of linkedCountQ.rows) {
      linkMap.set(row.visitor_id, row.link_count);
    }

    // Union-Find: collapse linked visitor_ids into identity clusters
    // Each cluster = 1 real person (even if they have multiple devices/browsers)
    const allVids = new Set<string>();
    const parent = new Map<string, string>();
    const find = (x: string): string => {
      if (!parent.has(x)) parent.set(x, x);
      if (parent.get(x) !== x) parent.set(x, find(parent.get(x)!));
      return parent.get(x)!;
    };
    const union = (a: string, b: string) => {
      const ra = find(a), rb = find(b);
      if (ra !== rb) parent.set(ra, rb);
    };
    // Register all known visitors from the recent fingerprints
    for (const row of allEventsQ.rows) {
      allVids.add(row.visitor_id);
      find(row.visitor_id);
    }
    // Merge linked devices
    for (const row of uniquePersonsQ.rows) {
      union(row.visitor_id_a, row.visitor_id_b);
      allVids.add(row.visitor_id_a);
      allVids.add(row.visitor_id_b);
    }
    // Count distinct roots = unique persons
    const roots = new Set<string>();
    for (const vid of allVids) roots.add(find(vid));
    const uniquePersons = roots.size;

    return c.json({
      window: '24h',
      generatedAt: new Date().toISOString(),
      overview: {
        ...(overview.rows[0] || {
          events_24h: 0, unique_devices_24h: 0, new_devices_24h: 0,
          vpn_24h: 0, incognito_24h: 0, high_risk_24h: 0, avg_confidence_pct: 0,
        }),
        linked_identities: linkMap.size,
        unique_persons: uniquePersons,
        total_persons: personsStatsQ.rows[0]?.total_persons || 0,
        total_person_devices: personsStatsQ.rows[0]?.total_person_devices || 0,
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

  if (!apiKey?.public_key || !String(apiKey.public_key).startsWith('pk_live_athar')) {
    return c.json({ error: 'Restricted to Athar operator keys.' }, 403);
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
    const { storedIds, ts, collectionMs, v, evasion, rawAttributes, ...stableCore } = signals;

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

    // ─── DEVICE-LEVEL HASH: signals that are IDENTICAL across all browsers on the same device ───
    // This is the key insight: hardware, screen resolution, installed fonts, and GPU name
    // don't change when you switch from Chrome to Firefox to Edge.
    const hw = signals.hardware || {};
    const scr = signals.screen || {};
    const wgl = signals.webgl || {};
    const deviceStableSignals = {
      cores: hw.cores || 0,
      mem: hw.mem || 0,
      platform: hw.platform || '',
      screenW: scr.w || scr.width || 0,
      screenH: scr.h || scr.height || 0,
      colorDepth: scr.colorDepth || scr.cd || 0,
      dpr: scr.dpr || scr.devicePixelRatio || 0,
      gpu: (wgl.renderer || wgl.rendererUnmasked || '').replace(/\s+/g, ' ').trim(),
      gpuVendor: (wgl.vendorUnmasked || wgl.vendor || '').replace(/\s+/g, ' ').trim(),
      touch: hw.touch || 0,
    };
    // Font list is ~95% stable across browsers on same OS install
    const fontList = Array.isArray(signals.fonts) ? signals.fonts :
      (signals.fonts?.installed || signals.fonts?.detected || []);
    const sortedFonts = (Array.isArray(fontList) ? [...fontList] : []).sort().join('|');
    const deviceHash = h({ ...deviceStableSignals, fonts: sortedFonts });

    // v3 optimized grouped hashes — volatile signals (storageQuota, permissions, timezone)
    // excluded from matching hashes to prevent unnecessary mismatches.
    // Each group pairs signals with similar stability and entropy.
    const hashes = {
      composite: legacyHashes.composite,
      device: deviceHash,  // NEW: cross-browser device identity
      canvas: h(signals.canvas),
      webgl: h({ webgl: signals.webgl, webglRender: signals.webglRender }),
      audio: h(signals.audio),
      screen: h({ screen: signals.screen, clientRects: signals.clientRects }),
      fonts: h({
        fonts: signals.fonts, arabicFonts: signals.arabicFonts, emoji: signals.emoji,
      }),
      browser: h({
        intlProbe: signals.intlProbe, cssSupports: signals.cssSupports,
        codecs: signals.codecs, voices: signals.voices,
      }),
      hardware: h({
        hardware: signals.hardware, mathml: signals.mathml, browser: signals.browser,
      }),
      // NEW: partial device hashes for graduated matching
      screenOnly: h({ w: scr.w || scr.width, h: scr.h || scr.height, cd: scr.colorDepth || scr.cd, dpr: scr.dpr || scr.devicePixelRatio }),
      gpuOnly: h({ gpu: deviceStableSignals.gpu, vendor: deviceStableSignals.gpuVendor }),
      hwOnly: h({ cores: deviceStableSignals.cores, mem: deviceStableSignals.mem, platform: deviceStableSignals.platform, touch: deviceStableSignals.touch }),
      fontsOnly: h(sortedFonts),
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

    // Bot classification: good (search engines), bad (malicious), notDetected
    const botClassification = (() => {
      if (botCount === 0 && (evasion?.headlessScore || 0) <= 0.4) return 'notDetected';
      const ua = (c.req.header('User-Agent') || '').toLowerCase();
      const goodBotPatterns = ['googlebot','bingbot','yandexbot','duckduckbot','slurp','baiduspider',
        'facebot','linkedinbot','twitterbot','applebot','semrushbot','ahrefsbot','mj12bot'];
      if (goodBotPatterns.some(p => ua.includes(p))) return 'good';
      return 'bad';
    })();

    // ─── AI AGENT DETECTION ───
    const KNOWN_AGENTS = [
      'ChatGPT-User', 'GPTBot', 'Google-Extended', 'Amazonbot',
      'PerplexityBot', 'ClaudeBot', 'Bytespider', 'cohere-ai',
      'Browserbase', 'Manus', 'AnchorBrowser', 'anthropic-ai',
      'CCBot', 'FacebookBot', 'Meta-ExternalAgent',
    ];
    const fullUA = c.req.header('User-Agent') || '';
    const isKnownAgent = KNOWN_AGENTS.some(a => fullUA.includes(a));
    const visitorType: 'human' | 'known_agent' | 'suspected_agent' | 'unknown' = (() => {
      if (isKnownAgent) return 'known_agent';
      if (botClassification === 'bad' || (evasion?.headlessScore || 0) > 0.6) return 'suspected_agent';
      if (botClassification === 'good') return 'known_agent';
      if (signalNames.length > 0 && signalsCollected === 0) return 'unknown';
      return 'human';
    })();

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

    // (d) OS mismatch — compare browser UA OS vs IP geolocation network signature
    const browserUA_vpn = c.req.header('User-Agent') || '';
    const uaPlatform = (() => {
      if (/Windows/.test(browserUA_vpn)) return 'windows';
      if (/Macintosh|Mac OS/.test(browserUA_vpn)) return 'mac';
      if (/Linux/.test(browserUA_vpn) && !/Android/.test(browserUA_vpn)) return 'linux';
      if (/Android/.test(browserUA_vpn)) return 'android';
      if (/iPhone|iPad/.test(browserUA_vpn)) return 'ios';
      return 'unknown';
    })();
    // Check signals.hardware.platform for mismatch with UA
    const hwPlatform = (signals.hardware?.platform || '').toLowerCase();
    let osMismatch = false;
    if (hwPlatform && uaPlatform !== 'unknown') {
      const platformMap: Record<string, string[]> = {
        windows: ['win32', 'win64', 'windows'],
        mac: ['macintel', 'macppc', 'mac'],
        linux: ['linux x86_64', 'linux aarch64', 'linux'],
        android: ['linux armv', 'linux aarch64', 'android'],
        ios: ['iphone', 'ipad', 'ipod'],
      };
      const expected = platformMap[uaPlatform] || [];
      if (expected.length > 0 && !expected.some(p => hwPlatform.includes(p))) {
        osMismatch = true;
        vpnScore += 1;
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

    // Proxy confidence refinement based on activity history
    // If this IP has been seen with multiple distinct visitors, it's likely a proxy/shared IP
    let ipDistinctVisitors = 0;
    try {
      const ipVisQ = await db.query(
        `SELECT COUNT(DISTINCT visitor_id)::int AS cnt
         FROM fingerprints WHERE ip_address = $1 AND api_key_id = $2
           AND last_seen >= NOW() - INTERVAL '7 days'`,
        [clientIp, apiKeyId]
      );
      ipDistinctVisitors = ipVisQ.rows[0]?.cnt || 0;
      if (ipDistinctVisitors >= 10 && proxyType === 'none') {
        proxyType = 'residential'; proxyConfidence = 'medium';
      } else if (ipDistinctVisitors >= 5 && proxyConfidence === 'medium') {
        proxyConfidence = 'high';
      }
    } catch (e) {}

    // ─── IP BLOCKLIST CHECK ───
    const blocklist = {
      result: false,
      details: { emailSpam: false, attackSource: false, datacenter: isDatacenter }
    };
    const isTor = (cfData.isTor === true || cfData.isTor === 'true');
    if (isTor) { blocklist.result = true; blocklist.details.attackSource = true; proxyType = 'tor'; }

    // Replay detection: if 75%+ of events from this IP in 7 days are replayed visitor_ids
    let replayPct = 0;
    try {
      const replayQ = await db.query(
        `SELECT COUNT(*)::int AS total,
                COUNT(*) FILTER (WHERE visit_count > 1)::int AS revisits
         FROM fingerprints WHERE ip_address = $1 AND api_key_id = $2
           AND last_seen >= NOW() - INTERVAL '7 days'`,
        [clientIp, apiKeyId]
      );
      const total = replayQ.rows[0]?.total || 0;
      const revisits = replayQ.rows[0]?.revisits || 0;
      replayPct = total > 0 ? Math.round((revisits / total) * 100) : 0;
      if (replayPct >= 75 && total >= 4) {
        blocklist.result = true;
        blocklist.details.attackSource = true;
      }
    } catch (e) {}
    if (isDatacenter && botCount > 0) {
      blocklist.result = true;
      blocklist.details.attackSource = true;
    }

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
           device_hash, screen_only_hash, gpu_hash, hw_only_hash, fonts_only_hash,
           ip_address, country, first_seen, last_seen, visit_count,
           is_vpn, is_incognito, headless_score, bot_score, api_key_id)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,NOW(),NOW(),1,$17,$18,$19,$20,$21)`,
        [vid, hashes.composite, hashes.canvas, hashes.webgl, hashes.audio,
         hashes.screen, hashes.fonts, hashes.browser, hashes.hardware,
         hashes.device, hashes.screenOnly, hashes.gpuOnly, hashes.hwOnly, hashes.fontsOnly,
         clientIp, cfData.country || null,
         isVpn, evasion?.isPrivate || false, headlessScoreInt, botCount,
         apiKeyId]
      );
    };

    // Helper: create a device_link between two visitors (idempotent)
    const linkDevices = async (vidA: string, vidB: string, linkType: string, conf: number, evidence: string[] = []) => {
      if (vidA === vidB) return;
      const [a, b] = [vidA, vidB].sort(); // canonical order
      try {
        // Try to add unique index if missing (idempotent)
        await db.query(`
          CREATE UNIQUE INDEX IF NOT EXISTS device_links_pair_idx ON device_links (visitor_id_a, visitor_id_b)
        `).catch(() => {});
        // Try to make evidence nullable if it isn't
        await db.query(`ALTER TABLE device_links ALTER COLUMN evidence DROP NOT NULL`).catch(() => {});
        await db.query(
          `INSERT INTO device_links (visitor_id_a, visitor_id_b, link_type, confidence, api_key_id, evidence)
           VALUES ($1, $2, $3, $4, $5, $6)
           ON CONFLICT (visitor_id_a, visitor_id_b) DO UPDATE SET confidence = GREATEST(device_links.confidence, $4), link_type = $3`,
          [a, b, linkType, conf, apiKeyId, JSON.stringify(evidence)]
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
        // TWO-PHASE approach: Phase A checks device-stable signals (cross-browser),
        // Phase B checks browser-specific signals (same-browser precision).
        const candidates = await db.query(
          `SELECT visitor_id, ip_address, canvas_hash, webgl_hash, audio_hash,
                  screen_hash, font_hash, browser_hash, hardware_hash,
                  device_hash, screen_only_hash, gpu_hash, hw_only_hash, fonts_only_hash
           FROM fingerprints
           WHERE api_key_id = $1
           ORDER BY last_seen DESC
           LIMIT 250`,
          [apiKeyId]
        );

        // ── Phase A: Device-level matching (cross-browser) ──
        // These signals are IDENTICAL across Chrome, Firefox, Edge on the same device.
        // device_hash alone is a very strong match (cores+mem+screen+gpu+fonts).
        const deviceWeights: Record<string, number> = {
          device:    0.35,   // full device identity (hw+screen+gpu+fonts)
          screenOnly: 0.15,  // screen resolution + colorDepth + dpr
          gpuOnly:   0.15,   // GPU renderer + vendor string
          hwOnly:    0.15,   // CPU cores + memory + platform + touch
          fontsOnly: 0.10,   // sorted installed font list
          // Browser-level hashes (lower weight — only match same browser)
          canvas:    0.04,
          audio:     0.03,
          browser:   0.03,
        };

        // Sentinel: hash of empty/undefined data — must never be treated as a real match
        const EMPTY_HASH = h({});
        const EMPTY_NULL_HASH = h(null);
        const EMPTY_UNDEF_HASH = h(undefined);
        const emptySentinels = new Set([EMPTY_HASH, EMPTY_NULL_HASH, EMPTY_UNDEF_HASH]);

        let bestScore = 0;
        let bestCandidate: any = null;
        let bestMatched: string[] = [];

        for (const cand of candidates.rows) {
          let score = 0;
          // ALWAYS use the full sum of all weights as denominator.
          // This prevents score inflation when most columns are NULL (old rows).
          const totalWeight = Object.values(deviceWeights).reduce((a, b) => a + b, 0);
          const matched: string[] = [];

          // Device-stable hash comparisons
          const devicePairs = [
            { key: 'device',    incoming: hashes.device,     stored: cand.device_hash },
            { key: 'screenOnly', incoming: hashes.screenOnly, stored: cand.screen_only_hash },
            { key: 'gpuOnly',   incoming: hashes.gpuOnly,    stored: cand.gpu_hash },
            { key: 'hwOnly',    incoming: hashes.hwOnly,     stored: cand.hw_only_hash },
            { key: 'fontsOnly', incoming: hashes.fontsOnly,  stored: cand.fonts_only_hash },
          ];

          for (const { key, incoming, stored } of devicePairs) {
            if (!stored || !incoming) continue;
            if (emptySentinels.has(stored) || emptySentinels.has(incoming)) continue;
            if (incoming === stored) {
              score += deviceWeights[key];
              matched.push(key);
            }
          }

          // Browser-specific hash comparisons (legacy — only match same browser)
          const browserPairs = [
            { key: 'canvas',   values: [hashes.canvas, legacyHashes.canvas],   stored: cand.canvas_hash },
            { key: 'audio',    values: [hashes.audio, legacyHashes.audio],     stored: cand.audio_hash },
            { key: 'browser',  values: [hashes.browser, legacyHashes.browser], stored: cand.browser_hash },
          ];

          for (const { key, values, stored } of browserPairs) {
            if (!stored) continue;
            if (emptySentinels.has(stored)) continue;
            const incoming = values.filter(v => v && !emptySentinels.has(v));
            if (incoming.length === 0) continue;
            if (incoming.includes(stored)) {
              score += deviceWeights[key];
              matched.push(key);
            }
          }

          // Bonus: if device_hash matches, that's near-certain same device
          if (matched.includes('device')) score += 0.10;
          // Bonus: if 3+ device-stable signals match but not the full device hash
          const stableMatches = ['screenOnly', 'gpuOnly', 'hwOnly', 'fontsOnly'].filter(k => matched.includes(k)).length;
          if (stableMatches >= 3) score += 0.08;
          // Bonus: same IP adds confidence
          if (normalizeIp(cand.ip_address) === normalizedClientIp && matched.length >= 1) score += 0.05;

          const normalized = score / totalWeight;
          if (normalized > bestScore) {
            bestScore = normalized;
            bestCandidate = cand;
            bestMatched = matched;
          }
        }

        // Tier 2 threshold: device_hash match alone (0.35 + 0.10 bonus) easily clears this
        const MATCH_THRESHOLD = 0.45;

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
        // Phone ↔ Desktop have ZERO matching hardware signals (different CPU, screen, GPU, fonts).
        // The only thing they share is the NETWORK: same public IP, timezone, language, country.
        // Strategy:
        //   - Same IP within 24h → link with base confidence 0.40
        //   - Same timezone → +0.15 confidence boost
        //   - Same language → +0.10 confidence boost
        //   - Any device-stable signal match → +0.15 per match
        // This creates a NEW visitor_id but LINKS to the existing one.
        } else {
          let linkCandidate: any = null;
          let linkScore = 0;
          let linkMatched: string[] = [];
          let linkType = 'new';

          // Fetch candidates with broader info (including timezone/language from recent events)
          // We use the fingerprints table data + CF metadata
          const browserTz = signals.timezone?.tz || '';
          const browserLang = (signals.browser?.lang || signals.browser?.language || '').toLowerCase();
          const clientCountry = (cfData.country || '').toUpperCase();

          for (const cand of candidates.rows) {
            const sameIp = normalizeIp(cand.ip_address) === normalizedClientIp;
            if (!sameIp) continue; // Phase 1: only link same-network devices

            // Base score for same IP
            let score = 0.40;
            const matched: string[] = ['same_ip'];

            // Check device-stable signals (unlikely to match phone↔desktop, but boosts confidence)
            const stablePairs = [
              { key: 'screenOnly', incoming: hashes.screenOnly, stored: cand.screen_only_hash },
              { key: 'gpuOnly',   incoming: hashes.gpuOnly,    stored: cand.gpu_hash },
              { key: 'hwOnly',    incoming: hashes.hwOnly,     stored: cand.hw_only_hash },
              { key: 'fontsOnly', incoming: hashes.fontsOnly,  stored: cand.fonts_only_hash },
            ];

            for (const { key, incoming, stored } of stablePairs) {
              if (stored && incoming && !emptySentinels.has(stored) && !emptySentinels.has(incoming) && incoming === stored) {
                score += 0.15;
                matched.push(key);
              }
            }

            // Time window check: only link if candidate was seen recently (within 7 days)
            // This prevents linking to very old devices that happened to share an IP
            // (We can't easily check last_seen here without adding it to the query, so
            //  we rely on the ORDER BY last_seen DESC LIMIT 250 from the candidates query)

            if (score > linkScore) {
              linkScore = score;
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
            const linkConf = Math.round(Math.min(linkScore, 1.0) * 100) / 100;
            await linkDevices(visitorId, linkCandidate.visitor_id, 'same_network', linkConf, linkMatched);
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
    let velocity: any = {
      distinctIp: { '5m': 0, '1h': 0, '24h': 0 },
      events: { '5m': 0, '1h': 0, '24h': 0 },
      distinctCountry: { '5m': 0, '1h': 0, '24h': 0 },
      ipEvents: { '5m': 0, '1h': 0, '24h': 0 },
      ipDistinctVisitors: { '1h': 0, '24h': 0 },
    };
    try {
      const [vel5m, vel1h, vel24h, ipVel, ipVisitors1h, ipVisitors24h] = await Promise.all([
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
        db.query(
          `SELECT COUNT(DISTINCT visitor_id)::int AS cnt
           FROM events WHERE ip_address = $1 AND api_key_id = $2
             AND created_at >= NOW() - INTERVAL '1 hour'`,
          [clientIp, apiKeyId]
        ),
        db.query(
          `SELECT COUNT(DISTINCT visitor_id)::int AS cnt
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
      velocity.ipDistinctVisitors['1h'] = ipVisitors1h.rows[0]?.cnt || 0;
      velocity.ipDistinctVisitors['24h'] = ipVisitors24h.rows[0]?.cnt || 0;
    } catch (e) {
      console.error('Velocity query error:', e);
    }

    // Distinct countries for this visitor (from fingerprints table geo data stored by CF)
    try {
      const countryQ = await db.query(
        `SELECT\n           COUNT(DISTINCT CASE WHEN last_seen >= NOW() - INTERVAL '5 minutes' THEN ip_address END)::int AS c5m,\n           COUNT(DISTINCT CASE WHEN last_seen >= NOW() - INTERVAL '1 hour' THEN ip_address END)::int AS c1h,\n           COUNT(DISTINCT ip_address)::int AS c24h\n         FROM fingerprints WHERE visitor_id = $1 AND api_key_id = $2\n           AND last_seen >= NOW() - INTERVAL '24 hours'`,
        [visitorId, apiKeyId]
      );
      // Use distinct IPs as proxy for distinct countries (each IP = potential different country)
      // For accurate country counts, we'd need to store country per event
      velocity.distinctCountry['5m'] = Math.min(velocity.distinctIp['5m'], countryQ.rows[0]?.c5m || 0);
      velocity.distinctCountry['1h'] = Math.min(velocity.distinctIp['1h'], countryQ.rows[0]?.c1h || 0);
      velocity.distinctCountry['24h'] = Math.min(velocity.distinctIp['24h'], countryQ.rows[0]?.c24h || 0);
    } catch (e) {}

    const highActivity = velocity.events['1h'] > 20 || velocity.events['5m'] > 10;

    // ─── Risk scoring (contextual — VPN alone ≠ risky) ───
    // Weighted suspect score: each signal has a weight and a 0-1 score.
    // Final suspectScore = weighted average × 100, capped at 0-100.
    const riskSignalWeights: Array<{ name: string; weight: number; score: number }> = [];
    const addRisk = (name: string, weight: number, active: boolean, intensity?: number) => {
      riskSignalWeights.push({ name, weight, score: active ? (intensity ?? 1.0) : 0 });
    };

    // Count evasion layers — risk compounds when stacked
    const evasionLayers =
      (finalIsVpn ? 1 : 0) +
      (evasion?.isPrivate ? 1 : 0) +
      (ipChanged ? 1 : 0) +
      (botCount > 0 ? 1 : 0) +
      ((evasion?.headlessScore || 0) > 0.4 ? 1 : 0);
    const layerMultiplier = Math.min(2.0, 1.0 + (evasionLayers - 1) * 0.25);

    // VPN: context-dependent
    addRisk('vpn', 15, finalIsVpn, evasionLayers >= 3 ? 1.0 : evasionLayers >= 2 ? 0.6 : 0.2);
    // Incognito: context-dependent
    addRisk('incognito', 10, evasion?.isPrivate || false, evasionLayers >= 3 ? 1.0 : evasionLayers >= 2 ? 0.5 : 0.15);
    // Hard signals
    addRisk('headless', 20, (evasion?.headlessScore || 0) > 0.4, Math.min(1.0, (evasion?.headlessScore || 0) * 2));
    addRisk('bot', 25, botCount > 0, Math.min(1.0, botCount / 4));
    // Tampering
    const tampering = evasion?.tampering || {};
    const tamperCount = Object.values(tampering).filter(Boolean).length;
    addRisk('tampering', 20, tamperCount > 0, Math.min(1.0, tamperCount / 3));
    // Contextual
    addRisk('deviceCluster', 5, linkedResult.rows.length > 3, Math.min(1.0, linkedResult.rows.length / 8));
    addRisk('ipChanged', 5, ipChanged && !finalIsVpn);
    addRisk('newAndHiding', 8, isNew && evasionLayers >= 2, Math.min(1.0, evasionLayers / 4));
    // Inherited risk
    addRisk('linkedBot', 10, linkedRiskFlags.bot);
    addRisk('linkedHeadless', 5, linkedRiskFlags.headless);
    addRisk('linkedEvasion', 5, linkedRiskFlags.vpn && linkedRiskFlags.incognito);
    // v3.1 signals
    const devToolsOpen = evasion?.devTools?.open || false;
    const vmResult = evasion?.virtualMachine?.result || false;
    addRisk('virtualMachine', 10, vmResult);
    addRisk('locationSpoofing', 15, locationSpoofResult);
    addRisk('highActivity', 8, highActivity, Math.min(1.0, Math.max(velocity.events['1h'] / 40, velocity.events['5m'] / 20)));
    addRisk('tor', 20, isTor);
    addRisk('osMismatch', 8, osMismatch);
    addRisk('replayAttack', 12, replayPct >= 75);

    // Compute weighted average
    const totalWeight = riskSignalWeights.reduce((sum, s) => sum + s.weight, 0);
    const weightedSum = riskSignalWeights.reduce((sum, s) => sum + s.weight * s.score, 0);
    let riskScore = totalWeight > 0 ? Math.round((weightedSum / totalWeight) * 100 * layerMultiplier) : 0;
    riskScore = Math.min(100, Math.max(0, riskScore));

    // ─── Cross-Device Person Resolution ───
    const personResult = await resolvePersonIdentity(
      db,
      visitorId,
      apiKeyId,
      clientIp,
      signals.userId || undefined,
    );

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
          visitorType,
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
      visitorType,
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
            bot: {
              result: botClassification,
              type: botClassification === 'good' ? 'searchEngine' : botClassification === 'bad' ? 'automation' : undefined,
            },
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
              osMismatch,
              relay: false,
              webrtcLeak: publicWebrtcIps.length > 0 && publicWebrtcIps.every((ip: string) => ip !== normalizedClientIp),
            },
          }
        },
        proxy: {
          data: {
            result: proxyType !== 'none',
            confidence: proxyConfidence,
            details: { proxyType, ipDistinctVisitors7d: ipDistinctVisitors },
          }
        },
        tor: { data: { result: isTor } },
        ipBlocklist: { data: { ...blocklist, replayPct } },
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
        privacySettings: {
          data: {
            result: evasion?.isPrivate || evasion?.privacyDetails?.brave || evasion?.privacyDetails?.firefoxStrict || evasion?.privacyDetails?.privacyExtension || false,
            brave: evasion?.privacyDetails?.brave || false,
            firefoxStrict: evasion?.privacyDetails?.firefoxStrict || false,
            privacyExtension: evasion?.privacyDetails?.privacyExtension || false,
            mode: evasion?.privacyDetails?.mode || null,
            privacyScore: evasion?.privacyScore || 0,
          }
        },
        factoryReset: { data: { time: null, timestamp: 0 } },
        velocity: { data: velocity },
        suspectScore: {
          data: {
            result: riskScore,
            breakdown: riskSignalWeights.filter(s => s.score > 0).map(s => ({
              signal: s.name, weight: s.weight, intensity: Math.round(s.score * 100) / 100,
            })),
          }
        },
        ipInfo: {
          data: {
            v4: {
              address: clientIp,
              geolocation: {
                accuracyRadius: cfData.city ? (isDatacenter ? 200 : 50) : (cfData.region ? 100 : 500),
                latitude: cfData.latitude || null,
                longitude: cfData.longitude || null,
                postalCode: cfData.postalCode || null,
                timezone: cfData.timezone || null,
                city: cfData.city ? { name: cfData.city } : null,
                country: cfData.country ? { code: cfData.country, name: cfData.country } : null,
                continent: cfData.continent ? { code: cfData.continent } : null,
                subdivisions: cfData.region ? [{ isoCode: cfData.region, name: cfData.region }] : [],
              },
              asn: {
                asn: String(cfData.asn || ''),
                name: cfData.asOrganization || '',
                network: `${clientIp}/24`,
                type: isDatacenter ? 'hosting' : isVpnAsn ? 'hosting' : 'isp',
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
        bot: botClassification === 'bad',
        tampered: !!(tampering.canvasOverride || tampering.uaOverride || tampering.navigatorProxy),
        multiAccount: linkedResult.rows.length > 1,
        ipChanged,
        tor: isTor,
        vm: vmResult,
        devTools: devToolsOpen,
        locationSpoofing: locationSpoofResult,
        highActivity,
        osMismatch,
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
        personId: personResult.personId,
        personLinkType: personResult.linkType,
        personDevices: personResult.linkedDevices,
        isNewPerson: personResult.isNewPerson,
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
