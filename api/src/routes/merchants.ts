import { Hono } from 'hono';
import { AppEnv } from '../types';
import { screenMerchant, SanctionsScreener } from '../screening';

const router = new Hono<AppEnv>();

// POST /v1/merchants — Create a new merchant for KYC onboarding
router.post('/v1/merchants', async (c) => {
  const db = c.get('db') as any;
  const apiKey = c.get('apiKey') as any;
  const apiKeyId = apiKey.id;
  const clientIp = c.req.header('CF-Connecting-IP') || '0.0.0.0';

  try {
    const body = await c.req.json() as any;
    const {
      legalNameAr, legalNameEn, tradeName, registrationNumber, taxId,
      businessType, industryCode, address, city, governorate, phone, email,
      owners: ownersRaw, owner: singleOwner,
    } = body;

    const owners = Array.isArray(ownersRaw) ? ownersRaw : (singleOwner ? [singleOwner] : []);
    if (!legalNameAr) return c.json({ error: 'legalNameAr is required' }, 400);

    const mResult = await db.query(
      `INSERT INTO merchants
        (api_key_id, legal_name_ar, legal_name_en, trade_name, registration_number,
         tax_id, business_type, industry_code, address, city, governorate, phone, email,
         kyc_status, screening_status)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'pending','pending')
       RETURNING *`,
      [apiKeyId, legalNameAr, legalNameEn || null, tradeName || null,
       registrationNumber || null, taxId || null, businessType || null,
       industryCode || null, address || null, city || null, governorate || null,
       phone || null, email || null]
    );
    const merchant = mResult.rows[0];

    const insertedOwners: any[] = [];
    if (Array.isArray(owners) && owners.length > 0) {
      for (const o of owners) {
        if (!o.fullNameAr) continue;
        const oResult = await db.query(
          `INSERT INTO merchant_owners
            (merchant_id, full_name_ar, full_name_en, father_name_ar, grandfather_name_ar,
             family_name_ar, date_of_birth, nationality, national_id, passport_number,
             ownership_pct, role, is_ubo, screening_status)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'pending')
           RETURNING *`,
          [merchant.id, o.fullNameAr, o.fullNameEn || null, o.fatherNameAr || null,
           o.grandfatherNameAr || null, o.familyNameAr || null, o.dateOfBirth || null,
           o.nationality || null, o.nationalId || null, o.passportNumber || null,
           o.ownershipPct != null ? o.ownershipPct : null, o.role || null, o.isUbo || false]
        );
        insertedOwners.push(oResult.rows[0]);
      }
    }

    await db.query(
      `INSERT INTO compliance_audit_log (merchant_id, action, actor, details, ip_address)
       VALUES ($1, 'merchant_created', $2, $3::jsonb, $4)`,
      [merchant.id, apiKey.public_key, JSON.stringify({
        legalNameAr, legalNameEn, ownerCount: insertedOwners.length,
      }), clientIp]
    );

    return c.json({ merchant: { ...merchant, owners: insertedOwners } }, 201);
  } catch (err: any) {
    console.error('Create merchant error:', err);
    return c.json({ error: 'Failed to create merchant', details: err.message }, 500);
  }
});

// GET /v1/merchants — List all merchants for this API key
router.get('/v1/merchants', async (c) => {
  const db = c.get('db') as any;
  const apiKey = c.get('apiKey') as any;
  const apiKeyId = apiKey.id;
  const status = c.req.query('status');

  try {
    let sql = `
      SELECT m.*,
        (SELECT COUNT(*)::int FROM merchant_owners WHERE merchant_id = m.id) AS owner_count,
        (SELECT COUNT(*)::int FROM merchant_owners WHERE merchant_id = m.id AND screening_status = 'clear') AS owners_clear,
        (SELECT COUNT(*)::int FROM merchant_owners WHERE merchant_id = m.id AND screening_status = 'hit') AS owners_hit,
        (SELECT COUNT(*)::int FROM merchant_alerts WHERE merchant_id = m.id AND resolved = false) AS open_alerts
      FROM merchants m
      WHERE m.api_key_id = $1
    `;
    const params: any[] = [apiKeyId];

    if (status && ['pending', 'approved', 'rejected', 'under_review'].includes(status)) {
      sql += ` AND m.kyc_status = $2`;
      params.push(status);
    }
    sql += ` ORDER BY m.created_at DESC`;

    const result = await db.query(sql, params);
    return c.json({ merchants: result.rows, total: result.rows.length });
  } catch (err: any) {
    console.error('List merchants error:', err);
    return c.json({ error: 'Failed to list merchants', details: err.message }, 500);
  }
});

// GET /v1/merchants/:id — Get merchant details with owners, alerts, documents
router.get('/v1/merchants/:id', async (c) => {
  const db = c.get('db') as any;
  const apiKey = c.get('apiKey') as any;
  const merchantId = c.req.param('id');

  try {
    const mResult = await db.query(
      `SELECT * FROM merchants WHERE id = $1 AND api_key_id = $2`,
      [merchantId, apiKey.id]
    );
    if (mResult.rows.length === 0) return c.json({ error: 'Merchant not found' }, 404);
    const merchant = mResult.rows[0];

    const [ownersQ, alertsQ, docsQ, auditQ] = await Promise.all([
      db.query(`SELECT * FROM merchant_owners WHERE merchant_id = $1 ORDER BY ownership_pct DESC NULLS LAST`, [merchantId]),
      db.query(`SELECT * FROM merchant_alerts WHERE merchant_id = $1 ORDER BY created_at DESC`, [merchantId]),
      db.query(`SELECT * FROM merchant_documents WHERE merchant_id = $1 ORDER BY created_at DESC`, [merchantId]),
      db.query(`SELECT * FROM compliance_audit_log WHERE merchant_id = $1 ORDER BY created_at DESC LIMIT 50`, [merchantId]),
    ]);

    return c.json({
      merchant: {
        ...merchant,
        owners: ownersQ.rows,
        alerts: alertsQ.rows,
        documents: docsQ.rows,
        auditLog: auditQ.rows,
      },
    });
  } catch (err: any) {
    console.error('Get merchant error:', err);
    return c.json({ error: 'Failed to get merchant', details: err.message }, 500);
  }
});

// PATCH /v1/merchants/:id — Update merchant details or KYC status
router.patch('/v1/merchants/:id', async (c) => {
  const db = c.get('db') as any;
  const apiKey = c.get('apiKey') as any;
  const merchantId = c.req.param('id');
  const clientIp = c.req.header('CF-Connecting-IP') || '0.0.0.0';

  try {
    const existing = await db.query(
      `SELECT * FROM merchants WHERE id = $1 AND api_key_id = $2`,
      [merchantId, apiKey.id]
    );
    if (existing.rows.length === 0) return c.json({ error: 'Merchant not found' }, 404);
    const prev = existing.rows[0];

    const body = await c.req.json() as any;
    const allowedTransitions: Record<string, string[]> = {
      pending: ['under_review'],
      under_review: ['approved', 'rejected'],
      rejected: ['under_review'],
    };

    if (body.kycStatus) {
      const allowed = allowedTransitions[prev.kyc_status] || [];
      if (!allowed.includes(body.kycStatus)) {
        return c.json({
          error: `Cannot transition from '${prev.kyc_status}' to '${body.kycStatus}'`,
          allowedTransitions: allowed,
        }, 400);
      }
    }

    const sets: string[] = ['updated_at = NOW()'];
    const vals: any[] = [];
    let idx = 1;

    const fields: Record<string, string> = {
      kycStatus: 'kyc_status', legalNameAr: 'legal_name_ar', legalNameEn: 'legal_name_en',
      tradeName: 'trade_name', registrationNumber: 'registration_number', taxId: 'tax_id',
      businessType: 'business_type', industryCode: 'industry_code', address: 'address',
      city: 'city', governorate: 'governorate', phone: 'phone', email: 'email',
      riskRating: 'risk_rating',
    };
    for (const [jsKey, dbCol] of Object.entries(fields)) {
      if (body[jsKey] !== undefined) {
        sets.push(`${dbCol} = $${idx}`);
        vals.push(body[jsKey]);
        idx++;
      }
    }

    if (sets.length === 1) return c.json({ error: 'No fields to update' }, 400);

    vals.push(merchantId, apiKey.id);
    const result = await db.query(
      `UPDATE merchants SET ${sets.join(', ')} WHERE id = $${idx} AND api_key_id = $${idx + 1} RETURNING *`,
      vals
    );

    if (body.kycStatus) {
      await db.query(
        `INSERT INTO compliance_audit_log (merchant_id, action, actor, details, ip_address)
         VALUES ($1, 'kyc_status_change', $2, $3::jsonb, $4)`,
        [merchantId, apiKey.public_key, JSON.stringify({
          from: prev.kyc_status, to: body.kycStatus, reason: body.reason || null,
        }), clientIp]
      );
    }

    return c.json({ merchant: result.rows[0] });
  } catch (err: any) {
    console.error('Update merchant error:', err);
    return c.json({ error: 'Failed to update merchant', details: err.message }, 500);
  }
});

// POST /v1/merchants/:id/screen — Run sanctions screening for merchant + owners
router.post('/v1/merchants/:id/screen', async (c) => {
  const db = c.get('db') as any;
  const apiKey = c.get('apiKey') as any;
  const merchantId = c.req.param('id');
  const clientIp = c.req.header('CF-Connecting-IP') || '0.0.0.0';
  const osApiKey = c.env.OPENSANCTIONS_API_KEY;

  try {
    const result = await screenMerchant(db, merchantId, apiKey, clientIp, osApiKey);
    return c.json(result);
  } catch (err: any) {
    if (err.message === 'MERCHANT_NOT_FOUND') return c.json({ error: 'Merchant not found' }, 404);
    console.error('Screen merchant error:', err);
    return c.json({ error: 'Screening failed', details: err.message }, 500);
  }
});

// GET /v1/screening/stats — Sanctions list cache stats
router.get('/v1/screening/stats', async (c) => {
  const screener = SanctionsScreener.getInstance();
  const osEnabled = c.env.OPENSANCTIONS_API_KEY !== undefined;
  return c.json({
    ...screener.getStats(),
    openSanctions: { enabled: osEnabled, endpoint: osEnabled ? 'https://api.opensanctions.org/match/default' : null },
  });
});

export default router;
