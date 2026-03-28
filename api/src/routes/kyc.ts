import { Hono } from 'hono';
import { AppEnv } from '../types';

const router = new Hono<AppEnv>();

// POST /v1/merchants/:id/owners — Add a new owner to an existing merchant
router.post('/v1/merchants/:id/owners', async (c) => {
  const db = c.get('db') as any;
  const apiKey = c.get('apiKey') as any;
  const merchantId = c.req.param('id');
  const clientIp = c.req.header('CF-Connecting-IP') || '0.0.0.0';

  try {
    const mQ = await db.query(
      `SELECT id FROM merchants WHERE id = $1 AND api_key_id = $2`,
      [merchantId, apiKey.id]
    );
    if (mQ.rows.length === 0) return c.json({ error: 'Merchant not found' }, 404);

    const o = await c.req.json() as any;
    if (!o.fullNameAr) return c.json({ error: 'fullNameAr is required' }, 400);

    const oResult = await db.query(
      `INSERT INTO merchant_owners
        (merchant_id, full_name_ar, full_name_en, father_name_ar, grandfather_name_ar,
         family_name_ar, mother_name_ar, date_of_birth, place_of_birth, gender,
         nationality, national_id, passport_number, phone,
         occupation, source_of_funds,
         ownership_pct, role, is_ubo, screening_status)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,'pending')
       RETURNING *`,
      [merchantId, o.fullNameAr, o.fullNameEn || null, o.fatherNameAr || null,
       o.grandfatherNameAr || null, o.familyNameAr || null, o.motherNameAr || null,
       o.dateOfBirth || null, o.placeOfBirth || null, o.gender || null,
       o.nationality || null, o.nationalId || null, o.passportNumber || null, o.phone || null,
       o.occupation || null, o.sourceOfFunds || null,
       o.ownershipPct != null ? o.ownershipPct : null, o.role || null, o.isUbo || false]
    );

    await db.query(
      `INSERT INTO compliance_audit_log (merchant_id, action, actor, details, ip_address)
       VALUES ($1, 'owner_added', $2, $3::jsonb, $4)`,
      [merchantId, apiKey.public_key, JSON.stringify({
        ownerId: oResult.rows[0].id, fullNameAr: o.fullNameAr,
      }), clientIp]
    );

    return c.json({ owner: oResult.rows[0] }, 201);
  } catch (err: any) {
    console.error('Add owner error:', err);
    return c.json({ error: 'Failed to add owner', details: err.message }, 500);
  }
});

// PATCH /v1/owners/:id — Update owner KYC profile (extended CBI fields)
router.patch('/v1/owners/:id', async (c) => {
  const db = c.get('db') as any;
  const apiKey = c.get('apiKey') as any;
  const ownerId = c.req.param('id');
  const clientIp = c.req.header('CF-Connecting-IP') || '0.0.0.0';

  try {
    const ownerQ = await db.query(
      `SELECT o.*, m.api_key_id FROM merchant_owners o
       JOIN merchants m ON m.id = o.merchant_id
       WHERE o.id = $1 AND m.api_key_id = $2`,
      [ownerId, apiKey.id]
    );
    if (ownerQ.rows.length === 0) return c.json({ error: 'Owner not found' }, 404);

    const body = await c.req.json() as any;
    const allowedFields: Record<string, string> = {
      fullNameAr: 'full_name_ar', fullNameEn: 'full_name_en',
      fatherNameAr: 'father_name_ar', grandfatherNameAr: 'grandfather_name_ar',
      familyNameAr: 'family_name_ar', motherNameAr: 'mother_name_ar',
      dateOfBirth: 'date_of_birth', placeOfBirth: 'place_of_birth',
      gender: 'gender', nationality: 'nationality', secondaryNationality: 'secondary_nationality',
      maritalStatus: 'marital_status', educationLevel: 'education_level',
      nationalId: 'national_id', nationalIdIssueDate: 'national_id_issue_date',
      nationalIdExpiry: 'national_id_expiry', nationalIdIssuingOffice: 'national_id_issuing_office',
      civilStatusNumber: 'civil_status_number',
      passportNumber: 'passport_number', passportIssueDate: 'passport_issue_date',
      passportExpiry: 'passport_expiry',
      bloodType: 'blood_type', familyNumber: 'family_number',
      residencyCardNumber: 'residency_card_number',
      governorate: 'governorate', district: 'district', neighborhood: 'neighborhood',
      streetAddress: 'street_address', phone: 'phone',
      occupation: 'occupation', employerName: 'employer_name',
      monthlyIncome: 'monthly_income', incomeCurrency: 'income_currency',
      expectedMonthlyVolume: 'expected_monthly_volume',
      sourceOfFunds: 'source_of_funds', purposeOfAccount: 'purpose_of_account',
      isPepSelf: 'is_pep_self', isPepFamily: 'is_pep_family', pepDetails: 'pep_details',
      isBeneficialOwner: 'is_beneficial_owner', uboDetails: 'ubo_details',
      ownershipPct: 'ownership_pct', role: 'role', isUbo: 'is_ubo',
    };

    const sets: string[] = [];
    const vals: any[] = [];
    let idx = 1;
    for (const [camel, col] of Object.entries(allowedFields)) {
      if (body[camel] !== undefined) {
        sets.push(`${col} = $${idx}`);
        vals.push(body[camel] === '' ? null : body[camel]);
        idx++;
      }
    }
    if (sets.length === 0) return c.json({ error: 'No fields to update' }, 400);

    vals.push(ownerId);
    await db.query(`UPDATE merchant_owners SET ${sets.join(', ')} WHERE id = $${idx}`, vals);
    const updated = await db.query(`SELECT * FROM merchant_owners WHERE id = $1`, [ownerId]);

    await db.query(
      `INSERT INTO compliance_audit_log (merchant_id, action, actor, details, ip_address)
       VALUES ($1, 'owner_kyc_updated', $2, $3::jsonb, $4)`,
      [ownerQ.rows[0].merchant_id, apiKey.public_key, JSON.stringify({ ownerId, fields: Object.keys(body) }), clientIp]
    );

    return c.json({ owner: updated.rows[0] });
  } catch (err: any) {
    console.error('Update owner error:', err);
    return c.json({ error: 'Failed to update owner', details: err.message }, 500);
  }
});

// POST /v1/owners/:id/auto-fill — Auto-fill owner fields from OCR results
router.post('/v1/owners/:id/auto-fill', async (c) => {
  const db = c.get('db') as any;
  const apiKey = c.get('apiKey') as any;
  const ownerId = c.req.param('id');

  try {
    const ownerQ = await db.query(
      `SELECT o.*, m.api_key_id FROM merchant_owners o
       JOIN merchants m ON m.id = o.merchant_id
       WHERE o.id = $1 AND m.api_key_id = $2`,
      [ownerId, apiKey.id]
    );
    if (ownerQ.rows.length === 0) return c.json({ error: 'Owner not found' }, 404);

    const docs = await db.query(
      `SELECT doc_type, doc_side, ocr_result FROM merchant_documents
       WHERE owner_id = $1 AND ocr_status = 'completed' AND ocr_result IS NOT NULL
       ORDER BY created_at DESC`,
      [ownerId]
    );

    const updates: Record<string, any> = {};
    for (const doc of docs.rows) {
      const ext = doc.ocr_result?.extraction;
      if (!ext) continue;
      const getVal = (f: any) => (f && typeof f === 'object' && f.value) ? f.value : null;

      if (doc.doc_type === 'national_id' && doc.doc_side === 'front') {
        if (!updates.full_name_ar && getVal(ext.full_name_ar)) updates.full_name_ar = getVal(ext.full_name_ar);
        if (!updates.father_name_ar && getVal(ext.father_name_ar)) updates.father_name_ar = getVal(ext.father_name_ar);
        if (!updates.grandfather_name_ar && getVal(ext.grandfather_name_ar)) updates.grandfather_name_ar = getVal(ext.grandfather_name_ar);
        if (!updates.family_name_ar && getVal(ext.surname_ar)) updates.family_name_ar = getVal(ext.surname_ar);
        if (!updates.mother_name_ar && getVal(ext.mother_name_ar)) updates.mother_name_ar = getVal(ext.mother_name_ar);
        if (!updates.gender && getVal(ext.gender)) updates.gender = getVal(ext.gender);
        if (!updates.blood_type && getVal(ext.blood_type)) updates.blood_type = getVal(ext.blood_type);
        if (!updates.national_id && getVal(ext.national_id_number)) updates.national_id = getVal(ext.national_id_number);
        if (!updates.civil_status_number && getVal(ext.civil_status_number)) updates.civil_status_number = getVal(ext.civil_status_number);
        if (!updates.nationality && getVal(ext.nationality)) updates.nationality = getVal(ext.nationality);
      }
      if (doc.doc_type === 'national_id' && doc.doc_side === 'back') {
        if (!updates.date_of_birth && getVal(ext.date_of_birth)) updates.date_of_birth = getVal(ext.date_of_birth);
        if (!updates.place_of_birth && getVal(ext.place_of_birth)) updates.place_of_birth = getVal(ext.place_of_birth);
        if (!updates.national_id_issue_date && getVal(ext.issue_date)) updates.national_id_issue_date = getVal(ext.issue_date);
        if (!updates.national_id_expiry && getVal(ext.expiry_date)) updates.national_id_expiry = getVal(ext.expiry_date);
        if (!updates.national_id_issuing_office && getVal(ext.issuing_authority)) updates.national_id_issuing_office = getVal(ext.issuing_authority);
        if (!updates.family_number && getVal(ext.family_number)) updates.family_number = getVal(ext.family_number);
      }
      if (doc.doc_type === 'passport') {
        if (!updates.full_name_en && getVal(ext.full_name_en)) updates.full_name_en = getVal(ext.full_name_en);
        if (!updates.passport_number && getVal(ext.passport_number)) updates.passport_number = getVal(ext.passport_number);
        if (!updates.passport_issue_date && getVal(ext.issue_date)) updates.passport_issue_date = getVal(ext.issue_date);
        if (!updates.passport_expiry && getVal(ext.expiry_date)) updates.passport_expiry = getVal(ext.expiry_date);
        if (!updates.date_of_birth && getVal(ext.date_of_birth)) updates.date_of_birth = getVal(ext.date_of_birth);
        if (!updates.nationality && getVal(ext.nationality)) updates.nationality = getVal(ext.nationality);
      }
      if (doc.doc_type === 'resident_id') {
        if (!updates.residency_card_number && getVal(ext.form_number)) updates.residency_card_number = getVal(ext.form_number);
        if (!updates.neighborhood && getVal(ext.neighborhood)) updates.neighborhood = getVal(ext.neighborhood);
        if (!updates.district && getVal(ext.district)) updates.district = getVal(ext.district);
        if (!updates.street_address && getVal(ext.residential_address)) updates.street_address = getVal(ext.residential_address);
      }
    }

    if (Object.keys(updates).length === 0) {
      return c.json({ message: 'No OCR data to auto-fill', filled: 0 });
    }

    const sets: string[] = [];
    const vals: any[] = [];
    let idx = 1;
    for (const [col, val] of Object.entries(updates)) {
      sets.push(`${col} = $${idx}`);
      vals.push(val);
      idx++;
    }
    vals.push(ownerId);
    await db.query(`UPDATE merchant_owners SET ${sets.join(', ')} WHERE id = $${idx}`, vals);

    return c.json({ message: 'Auto-fill complete', filled: Object.keys(updates).length, fields: Object.keys(updates) });
  } catch (err: any) {
    console.error('Auto-fill error:', err);
    return c.json({ error: 'Failed to auto-fill', details: err.message }, 500);
  }
});

// GET /v1/merchants/:id/kyc-report — Generate full CBI-compliant KYC report
router.get('/v1/merchants/:id/kyc-report', async (c) => {
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

    const [ownersQ, docsQ, alertsQ, screeningQ, auditQ] = await Promise.all([
      db.query(`SELECT * FROM merchant_owners WHERE merchant_id = $1 ORDER BY ownership_pct DESC NULLS LAST`, [merchantId]),
      db.query(`SELECT id, doc_type, doc_side, file_name, mime_type, file_size, verification_status, ocr_status, storage_path, created_at FROM merchant_documents WHERE merchant_id = $1 ORDER BY created_at`, [merchantId]),
      db.query(`SELECT * FROM merchant_alerts WHERE merchant_id = $1 ORDER BY created_at DESC`, [merchantId]),
      db.query(`SELECT * FROM screening_results WHERE merchant_id = $1 ORDER BY created_at DESC`, [merchantId]),
      db.query(`SELECT action, actor, details, created_at FROM compliance_audit_log WHERE merchant_id = $1 ORDER BY created_at DESC LIMIT 50`, [merchantId]),
    ]);

    const owners = ownersQ.rows;
    const documents = docsQ.rows;

    const requiredDocTypes = ['national_id_front', 'national_id_back', 'passport', 'resident_id'];
    const ownerReports = owners.map((o: any) => {
      const ownerDocs = documents.filter((d: any) => d.owner_id === o.id);
      const docMap: Record<string, any> = {};
      for (const d of ownerDocs) {
        const key = d.doc_type === 'national_id' ? `${d.doc_type}_${d.doc_side}` : d.doc_type;
        docMap[key] = { id: d.id, status: d.verification_status, ocr: d.ocr_status, fileName: d.file_name };
      }
      const missingDocs = requiredDocTypes.filter(t => !docMap[t]);
      const allVerified = ownerDocs.length > 0 && ownerDocs.every((d: any) => d.verification_status === 'verified');

      const requiredFields = [
        'full_name_ar', 'father_name_ar', 'grandfather_name_ar', 'family_name_ar',
        'mother_name_ar', 'date_of_birth', 'place_of_birth', 'gender', 'nationality',
        'national_id', 'national_id_issue_date', 'national_id_expiry',
        'governorate', 'district', 'phone',
        'occupation', 'source_of_funds',
      ];
      const missingFields = requiredFields.filter(f => !o[f]);
      const completeness = Math.round(((requiredFields.length - missingFields.length) / requiredFields.length) * 100);

      return {
        id: o.id,
        fullNameAr: o.full_name_ar,
        fullNameEn: o.full_name_en,
        personalData: {
          fullNameAr: o.full_name_ar, fatherNameAr: o.father_name_ar,
          grandfatherNameAr: o.grandfather_name_ar, familyNameAr: o.family_name_ar,
          motherNameAr: o.mother_name_ar, fullNameEn: o.full_name_en,
          dateOfBirth: o.date_of_birth, placeOfBirth: o.place_of_birth,
          gender: o.gender, nationality: o.nationality,
          secondaryNationality: o.secondary_nationality, maritalStatus: o.marital_status,
          educationLevel: o.education_level, bloodType: o.blood_type,
        },
        identification: {
          nationalId: o.national_id, civilStatusNumber: o.civil_status_number,
          nationalIdIssueDate: o.national_id_issue_date, nationalIdExpiry: o.national_id_expiry,
          nationalIdIssuingOffice: o.national_id_issuing_office, familyNumber: o.family_number,
          passportNumber: o.passport_number, passportIssueDate: o.passport_issue_date,
          passportExpiry: o.passport_expiry,
        },
        address: {
          governorate: o.governorate, district: o.district, neighborhood: o.neighborhood,
          streetAddress: o.street_address, residencyCardNumber: o.residency_card_number, phone: o.phone,
        },
        employment: {
          occupation: o.occupation, employerName: o.employer_name,
          monthlyIncome: o.monthly_income, incomeCurrency: o.income_currency,
          expectedMonthlyVolume: o.expected_monthly_volume,
          sourceOfFunds: o.source_of_funds, purposeOfAccount: o.purpose_of_account,
        },
        compliance: {
          isPepSelf: o.is_pep_self, isPepFamily: o.is_pep_family, pepDetails: o.pep_details,
          isBeneficialOwner: o.is_beneficial_owner, uboDetails: o.ubo_details,
          screeningStatus: o.screening_status, pepStatus: o.pep_status,
        },
        ownershipPct: o.ownership_pct,
        role: o.role,
        documents: docMap,
        missingDocs,
        missingFields,
        completeness,
        allDocsVerified: allVerified,
      };
    });

    const overallCompleteness = ownerReports.length > 0
      ? Math.round(ownerReports.reduce((s: number, o: any) => s + o.completeness, 0) / ownerReports.length)
      : 0;
    const allDocsVerified = ownerReports.every((o: any) => o.allDocsVerified);
    const allFieldsComplete = ownerReports.every((o: any) => o.missingFields.length === 0);
    const allDocsUploaded = ownerReports.every((o: any) => o.missingDocs.length === 0);
    const openAlerts = alertsQ.rows.filter((a: any) => a.status === 'open' || (!a.status && !a.resolved));
    const screeningClear = screeningQ.rows.length === 0 || screeningQ.rows.every((s: any) => (s.match_score || 0) < 0.7);
    const kycReady = allDocsVerified && allFieldsComplete && allDocsUploaded && openAlerts.length === 0 && screeningClear;

    return c.json({
      report: {
        merchantId: merchant.id,
        merchantName: merchant.legal_name_ar,
        merchantNameEn: merchant.legal_name_en,
        tradeName: merchant.trade_name,
        registrationNumber: merchant.registration_number,
        kycStatus: merchant.kyc_status,
        generatedAt: new Date().toISOString(),
        overall: {
          completeness: overallCompleteness,
          allDocsVerified, allFieldsComplete, allDocsUploaded,
          screeningClear, openAlerts: openAlerts.length, kycReady,
        },
        owners: ownerReports,
        alerts: alertsQ.rows,
        screening: screeningQ.rows,
        auditTrail: auditQ.rows,
      },
    });
  } catch (err: any) {
    console.error('KYC report error:', err);
    return c.json({ error: 'Failed to generate KYC report', details: err.message }, 500);
  }
});

export default router;
