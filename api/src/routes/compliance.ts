import { Hono } from 'hono';
import { AppEnv } from '../types';
import { getPool } from '../db';
import { screenMerchant } from '../screening';

const router = new Hono<AppEnv>();

// GET /v1/compliance/dashboard — Overview stats
router.get('/v1/compliance/dashboard', async (c) => {
  const db = c.get('db') as any;
  const apiKey = c.get('apiKey') as any;
  try {
    const [merchantsQ, screeningQ, alertsQ, ownersQ, riskQ, recentQ] = await Promise.all([
      db.query(`
        SELECT
          COUNT(*)::int AS total,
          COUNT(*) FILTER (WHERE kyc_status = 'pending')::int AS pending,
          COUNT(*) FILTER (WHERE kyc_status = 'under_review')::int AS under_review,
          COUNT(*) FILTER (WHERE kyc_status = 'approved')::int AS approved,
          COUNT(*) FILTER (WHERE kyc_status = 'rejected')::int AS rejected
        FROM merchants
      `),
      db.query(`
        SELECT
          COUNT(DISTINCT COALESCE(owner_id, merchant_id))::int AS total_screened,
          COUNT(*) FILTER (WHERE match_score >= 0.75)::int AS matches_found,
          (SELECT COUNT(*)::int FROM merchant_owners WHERE screening_status = 'pending') +
          (SELECT COUNT(*)::int FROM merchants WHERE screening_status = 'pending') AS pending_review,
          COUNT(*) FILTER (WHERE created_at >= CURRENT_DATE)::int AS cleared_today
        FROM screening_results
      `),
      db.query(`
        SELECT
          COUNT(*) FILTER (WHERE status = 'open')::int AS open,
          COUNT(*) FILTER (WHERE status = 'open' AND severity = 'critical')::int AS critical,
          COUNT(*) FILTER (WHERE status = 'open' AND severity = 'high')::int AS high,
          COUNT(*) FILTER (WHERE status = 'open' AND severity = 'medium')::int AS medium,
          COUNT(*) FILTER (WHERE status = 'open' AND severity = 'low')::int AS low,
          COUNT(*) FILTER (WHERE status != 'open' AND resolved_at >= NOW() - INTERVAL '7 days')::int AS resolved_this_week
        FROM merchant_alerts
      `),
      db.query(`
        SELECT
          COUNT(*)::int AS total,
          COUNT(*) FILTER (WHERE pep_status = 'flagged')::int AS pep_matches,
          COUNT(*) FILTER (WHERE screening_status = 'flagged')::int AS sanction_matches
        FROM merchant_owners
      `),
      db.query(`
        SELECT
          COUNT(*) FILTER (WHERE risk_rating = 'high')::int AS high,
          COUNT(*) FILTER (WHERE risk_rating = 'medium')::int AS medium,
          COUNT(*) FILTER (WHERE risk_rating = 'low')::int AS low
        FROM merchants
      `),
      db.query(`
        SELECT id, merchant_id, action, actor, details, ip_address, created_at
        FROM compliance_audit_log
        ORDER BY created_at DESC
        LIMIT 20
      `),
    ]);
    const m = merchantsQ.rows[0];
    const s = screeningQ.rows[0];
    const a = alertsQ.rows[0];
    const o = ownersQ.rows[0];
    const r = riskQ.rows[0];
    return c.json({
      merchants: { total: m.total, pending: m.pending, underReview: m.under_review, approved: m.approved, rejected: m.rejected },
      screening: { totalScreened: s.total_screened, pendingReview: s.pending_review, matchesFound: s.matches_found, clearedToday: s.cleared_today },
      alerts: { open: a.open, critical: a.critical, high: a.high, medium: a.medium, low: a.low, resolvedThisWeek: a.resolved_this_week },
      owners: { total: o.total, pepMatches: o.pep_matches, sanctionMatches: o.sanction_matches },
      riskDistribution: { high: r.high, medium: r.medium, low: r.low },
      recentActivity: recentQ.rows,
    });
  } catch (err: any) {
    console.error('Compliance dashboard error:', err);
    return c.json({ error: 'Failed to load compliance dashboard', details: err.message }, 500);
  }
});

// GET /v1/compliance/alerts — List alerts with filtering
router.get('/v1/compliance/alerts', async (c) => {
  const db = c.get('db') as any;
  const apiKey = c.get('apiKey') as any;
  const status = c.req.query('status');
  const severity = c.req.query('severity');
  const merchantId = c.req.query('merchantId');

  const conditions: string[] = [];
  const params: any[] = [];
  let idx = 1;
  if (status) { conditions.push(`a.status = $${idx++}`); params.push(status); }
  if (severity) { conditions.push(`a.severity = $${idx++}`); params.push(severity); }
  if (merchantId) { conditions.push(`a.merchant_id = $${idx++}`); params.push(merchantId); }
  const where = conditions.length > 0 ? 'WHERE ' + conditions.join(' AND ') : '';

  try {
    const result = await db.query(`
      SELECT a.*, m.legal_name_ar, m.legal_name_en, m.trade_name,
             o.full_name_ar AS owner_name_ar, o.full_name_en AS owner_name_en
      FROM merchant_alerts a
      LEFT JOIN merchants m ON a.merchant_id = m.id
      LEFT JOIN merchant_owners o ON a.owner_id = o.id
      ${where}
      ORDER BY
        CASE a.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
        a.created_at DESC
    `, params);
    return c.json({ alerts: result.rows, total: result.rows.length });
  } catch (err: any) {
    console.error('Compliance alerts error:', err);
    return c.json({ error: 'Failed to load alerts', details: err.message }, 500);
  }
});

// PATCH /v1/compliance/alerts/:id — Resolve an alert
router.patch('/v1/compliance/alerts/:id', async (c) => {
  const db = c.get('db') as any;
  const apiKey = c.get('apiKey') as any;
  const alertId = c.req.param('id');
  const clientIp = c.req.header('CF-Connecting-IP') || '0.0.0.0';
  let body: any;
  try { body = await c.req.json(); } catch { return c.json({ error: 'Invalid JSON body' }, 400); }
  const { status, resolution_notes, resolved_by } = body;
  const validStatuses = ['resolved', 'escalated', 'false_positive'];
  if (!status || !validStatuses.includes(status)) {
    return c.json({ error: `Invalid status. Must be one of: ${validStatuses.join(', ')}` }, 400);
  }
  try {
    const existing = await db.query('SELECT * FROM merchant_alerts WHERE id = $1', [alertId]);
    if (existing.rows.length === 0) return c.json({ error: 'Alert not found' }, 404);
    const alert = existing.rows[0];
    const updated = await db.query(`
      UPDATE merchant_alerts
      SET status = $1, resolution_notes = $2, resolved_by = $3, resolved_at = NOW(), resolved = true
      WHERE id = $4
      RETURNING *
    `, [status, resolution_notes || null, resolved_by || apiKey.public_key, alertId]);
    await db.query(
      `INSERT INTO compliance_audit_log (merchant_id, action, actor, details, ip_address)
       VALUES ($1, 'alert_resolved', $2, $3::jsonb, $4)`,
      [alert.merchant_id, apiKey.public_key, JSON.stringify({
        alertId, alertType: alert.alert_type, severity: alert.severity,
        status, resolution_notes: resolution_notes || null,
      }), clientIp],
    );
    return c.json({ alert: updated.rows[0] });
  } catch (err: any) {
    console.error('Alert resolve error:', err);
    return c.json({ error: 'Failed to resolve alert', details: err.message }, 500);
  }
});

// GET /v1/compliance/audit — Audit trail with pagination
router.get('/v1/compliance/audit', async (c) => {
  const db = c.get('db') as any;
  const apiKey = c.get('apiKey') as any;
  const entityType = c.req.query('entityType');
  const entityId = c.req.query('entityId');
  const from = c.req.query('from');
  const to = c.req.query('to');
  const page = Math.max(1, parseInt(c.req.query('page') || '1', 10));
  const limit = 50;
  const offset = (page - 1) * limit;

  const conditions: string[] = [];
  const params: any[] = [];
  let idx = 1;
  if (entityType === 'merchant' && entityId) {
    conditions.push(`merchant_id = $${idx++}`); params.push(entityId);
  } else if (entityType === 'owner' && entityId) {
    conditions.push(`details->>'ownerId' = $${idx++}`); params.push(entityId);
  } else if (entityType === 'alert' && entityId) {
    conditions.push(`details->>'alertId' = $${idx++}`); params.push(entityId);
  } else if (entityId) {
    conditions.push(`(merchant_id = $${idx} OR details->>'ownerId' = $${idx} OR details->>'alertId' = $${idx})`); params.push(entityId); idx++;
  }
  if (from) { conditions.push(`created_at >= $${idx++}`); params.push(from); }
  if (to) { conditions.push(`created_at <= $${idx++}`); params.push(to); }
  const where = conditions.length > 0 ? 'WHERE ' + conditions.join(' AND ') : '';

  try {
    const [countQ, dataQ] = await Promise.all([
      db.query(`SELECT COUNT(*)::int AS total FROM compliance_audit_log ${where}`, params),
      db.query(`
        SELECT * FROM compliance_audit_log ${where}
        ORDER BY created_at DESC
        LIMIT $${idx++} OFFSET $${idx++}
      `, [...params, limit, offset]),
    ]);
    const total = countQ.rows[0].total;
    return c.json({
      audit: dataQ.rows,
      pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
    });
  } catch (err: any) {
    console.error('Compliance audit error:', err);
    return c.json({ error: 'Failed to load audit trail', details: err.message }, 500);
  }
});

// POST /v1/compliance/screen-all — Batch rescreening
router.post('/v1/compliance/screen-all', async (c) => {
  const db = c.get('db') as any;
  const apiKey = c.get('apiKey') as any;
  const clientIp = c.req.header('CF-Connecting-IP') || '0.0.0.0';
  const osApiKey = c.env.OPENSANCTIONS_API_KEY;

  try {
    const staleQ = await db.query(`
      SELECT id FROM merchants
      WHERE last_screened_at IS NULL OR last_screened_at < NOW() - INTERVAL '24 hours'
    `);
    const merchantIds: string[] = staleQ.rows.map((r: any) => r.id);
    if (merchantIds.length === 0) {
      return c.json({ message: 'All merchants are up to date', queued: 0 }, 200);
    }

    await db.query(
      `INSERT INTO compliance_audit_log (action, actor, details, ip_address)
       VALUES ('batch_screening_started', $1, $2::jsonb, $3)`,
      [apiKey.public_key, JSON.stringify({ merchantCount: merchantIds.length, merchantIds }), clientIp],
    );

    c.executionCtx.waitUntil((async () => {
      let results = { screened: 0, failed: 0, errors: [] as string[] };
      for (const mid of merchantIds) {
        const bgDb = getPool(c.env.DATABASE_URL);
        try {
          await screenMerchant(bgDb, mid, apiKey, clientIp, osApiKey);
          results.screened++;
        } catch (err: any) {
          results.failed++;
          results.errors.push(`${mid}: ${err.message}`);
        }
      }
      const logDb = getPool(c.env.DATABASE_URL);
      try {
        await logDb.query(
          `INSERT INTO compliance_audit_log (action, actor, details, ip_address)
           VALUES ('batch_screening_completed', $1, $2::jsonb, $3)`,
          [apiKey.public_key, JSON.stringify(results), clientIp],
        );
      } catch (_) { /* best effort */ }
    })());

    return c.json({ message: 'Batch rescreening started', queued: merchantIds.length }, 202);
  } catch (err: any) {
    console.error('Batch screening error:', err);
    return c.json({ error: 'Failed to start batch screening', details: err.message }, 500);
  }
});

export default router;
