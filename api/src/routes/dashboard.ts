import { Hono } from 'hono';
import { AppEnv } from '../types';

const router = new Hono<AppEnv>();

router.get('/health', (c) => c.json({ status: 'ok', version: '2.0.0', edge: true }));
router.get('/ready', (c) => c.json({ ready: true }));

router.get('/stats', async (c) => {
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

// GET /v1/portal/dashboard — Unified dashboard for any API key holder
router.get('/v1/portal/dashboard', async (c) => {
  const db = c.get('db') as any;
  const apiKey = c.get('apiKey') as any;
  const apiKeyId = apiKey.id;
  try {
    const [merchantsQ, docsQ, alertsQ, ownersQ] = await Promise.all([
      db.query(`SELECT id, legal_name_ar, legal_name_en, trade_name, kyc_status, screening_status, risk_rating, created_at
                FROM merchants WHERE api_key_id = $1 ORDER BY created_at DESC`, [apiKeyId]),
      db.query(`SELECT d.id, d.merchant_id, d.doc_type, d.doc_side, d.verification_status, d.ocr_status, d.created_at
                FROM merchant_documents d JOIN merchants m ON m.id = d.merchant_id
                WHERE m.api_key_id = $1 ORDER BY d.created_at DESC`, [apiKeyId]),
      db.query(`SELECT a.id, a.merchant_id, a.alert_type, a.severity, a.status, a.details, a.created_at
                FROM merchant_alerts a JOIN merchants m ON m.id = a.merchant_id
                WHERE m.api_key_id = $1 ORDER BY a.created_at DESC`, [apiKeyId]),
      db.query(`SELECT o.merchant_id, o.id, o.full_name_ar, o.full_name_en, o.screening_status, o.pep_status,
                       o.kyc_completed, o.national_id, o.passport_number, o.ownership_pct, o.role
                FROM merchant_owners o JOIN merchants m ON m.id = o.merchant_id
                WHERE m.api_key_id = $1`, [apiKeyId]),
    ]);
    const merchants = merchantsQ.rows;
    const openAlerts = alertsQ.rows.filter((a: any) => a.status === 'open' || !a.status);
    return c.json({
      kycStats: {
        total: merchants.length,
        pending: merchants.filter((m: any) => m.kyc_status === 'pending').length,
        underReview: merchants.filter((m: any) => m.kyc_status === 'under_review').length,
        approved: merchants.filter((m: any) => m.kyc_status === 'approved').length,
        rejected: merchants.filter((m: any) => m.kyc_status === 'rejected').length,
      },
      docStats: {
        total: docsQ.rows.length,
        verified: docsQ.rows.filter((d: any) => d.verification_status === 'verified').length,
        pending: docsQ.rows.filter((d: any) => d.verification_status === 'pending').length,
      },
      openAlerts: openAlerts.length,
      merchants: merchants.map((m: any) => ({
        ...m,
        owners: ownersQ.rows.filter((o: any) => o.merchant_id === m.id),
        documents: docsQ.rows.filter((d: any) => d.merchant_id === m.id),
      })),
      recentAlerts: openAlerts.slice(0, 20),
    });
  } catch (err: any) {
    return c.json({ error: 'Dashboard query failed', details: err.message }, 500);
  }
});

// GET /v1/portal/activity — Activity feed
router.get('/v1/portal/activity', async (c) => {
  const db = c.get('db') as any;
  const apiKey = c.get('apiKey') as any;
  try {
    const result = await db.query(
      `SELECT c.id, c.action, c.actor, c.details, c.created_at, c.ip_address,
              m.legal_name_ar AS merchant_name
       FROM compliance_audit_log c
       LEFT JOIN merchants m ON m.id = c.merchant_id
       WHERE c.actor = $1 OR c.actor = 'system'
       ORDER BY c.created_at DESC LIMIT 100`,
      [apiKey.public_key]
    );
    return c.json({ activity: result.rows });
  } catch (err: any) {
    return c.json({ error: 'Failed to load activity', details: err.message }, 500);
  }
});

router.get('/v1/dashboard', async (c) => {
  const db = c.get('db') as any;
  const apiKey = c.get('apiKey') as any;

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
      db.query(
        `SELECT sub.visitor_id, COUNT(*)::int AS link_count
         FROM (
           SELECT visitor_id_a AS visitor_id FROM device_links
           UNION ALL
           SELECT visitor_id_b AS visitor_id FROM device_links
         ) sub
         GROUP BY sub.visitor_id`
      ).catch(() => ({ rows: [] })),
      db.query(
        `SELECT e.visitor_id, e.event_type, e.event_data, e.ip_address, e.created_at,
                k.name AS merchant_name, k.public_key
         FROM events e
         JOIN api_keys k ON k.id = e.api_key_id
         WHERE e.created_at >= NOW() - INTERVAL '24 hours'
         ORDER BY e.created_at DESC
         LIMIT 200`
      ).catch(() => ({ rows: [] })),
      db.query(
        `SELECT visitor_id_a, visitor_id_b FROM device_links`
      ).catch(() => ({ rows: [] })),
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
    for (const row of allEventsQ.rows) {
      allVids.add(row.visitor_id);
      find(row.visitor_id);
    }
    for (const row of uniquePersonsQ.rows) {
      union(row.visitor_id_a, row.visitor_id_b);
      allVids.add(row.visitor_id_a);
      allVids.add(row.visitor_id_b);
    }
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
        publicKey: row.public_key,
        createdAt: row.created_at,
      })),
    });
  } catch (err: any) {
    return c.json({ error: 'Dashboard query failed', details: err.message }, 500);
  }
});

export default router;
